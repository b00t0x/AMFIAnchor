// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 b00t0x

#include "kern_coretrust.hpp"

#include "kern_anchor.hpp"

namespace {
const char *coreTrustPaths[] {"/System/Library/Extensions/CoreTrust.kext/Contents/MacOS/CoreTrust"};
}

CoreTrustPolicy::PolicyFunction CoreTrustPolicy::orgSetRootPolicy {nullptr};
CoreTrustPolicy::LookupFunction CoreTrustPolicy::orgFindRoot {nullptr};
mach_vm_address_t CoreTrustPolicy::policyEntry {0};
mach_vm_address_t CoreTrustPolicy::lookupEntry {0};
CoreTrustPolicy::InstallStatus CoreTrustPolicy::installStatus {InstallStatus::Pending};
uint64_t CoreTrustPolicy::policyCalls {0};
uint64_t CoreTrustPolicy::lookupCalls {0};
uint64_t CoreTrustPolicy::nullPolicyCalls {0};
uint64_t CoreTrustPolicy::nullPolicyNativeSkipped {0};
bool CoreTrustPolicy::nativeNullPolicyNoOp {false};
KernelPatcher::KextInfo CoreTrustPolicy::coreTrust {
    "com.apple.kext.CoreTrust", coreTrustPaths, arrsize(coreTrustPaths), {true}, {}, 0
};

LiluAPI::Error CoreTrustPolicy::init() {
	return lilu.onKextLoad(&coreTrust, 1, processKext, nullptr);
}

void CoreTrustPolicy::processKext(
    void *, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size
) {
	if (index != coreTrust.loadIndex || installStatus != InstallStatus::Pending) {
		return;
	}

	policyEntry = patcher.solveSymbol(index, "_X509PolicySetFlagsForRoots");
	lookupEntry = patcher.solveSymbol(index, "_X509ChainGetAppleRootUsingKeyIdentifier");
	if (!policyEntry || !lookupEntry) {
		installStatus = InstallStatus::MissingSymbol;
		SYSLOG("policy", "missing CoreTrust root-selection symbols");
		patcher.clearError();
		return;
	}

	// A preexisting short route cannot be safely chained by Lilu. Keep both native
	// functions untouched in this case; placing AMFIAnchor first avoids this order.
	auto policyBytes = reinterpret_cast<const uint8_t *>(policyEntry);
	auto lookupBytes = reinterpret_cast<const uint8_t *>(lookupEntry);
	if (policyBytes[0] == 0xE9 || lookupBytes[0] == 0xE9) {
		installStatus = InstallStatus::PreexistingShortRoute;
		SYSLOG("policy", "preexisting short route; load AMFIAnchor before other root hooks");
		return;
	}

	// Inspect the native entry before routing replaces its bytes. Publish the
	// result before the hook can run; each policy call only reads this flag.
	__atomic_store_n(&nativeNullPolicyNoOp, hasNullPolicyNoOp(policyEntry, address, size), __ATOMIC_RELEASE);

	KernelPatcher::RouteRequest requests[] {
	    {"_X509PolicySetFlagsForRoots", wrapSetRootPolicy, orgSetRootPolicy},
	    {"_X509ChainGetAppleRootUsingKeyIdentifier", wrapFindRoot, orgFindRoot}
	};
	bool routed = patcher.routeMultipleLong(index, requests, arrsize(requests));
	installStatus = routed ? InstallStatus::Installed : InstallStatus::RoutingFailed;
	if (!routed) {
		SYSLOG("policy", "could not install root-selection hooks, error %d", patcher.getError());
	}
	patcher.clearError();
}

bool CoreTrustPolicy::hasNullPolicyNoOp(mach_vm_address_t entry, mach_vm_address_t address, size_t size) {
	// Observed native prefix: test rdi,rdi (3 bytes), jz rel32 (6 bytes).
	static constexpr size_t NullPolicyPrefixSize {9};
	if (size < NullPolicyPrefixSize || entry < address || entry - address > size - NullPolicyPrefixSize) {
		return false;
	}
	auto bytes = reinterpret_cast<const uint8_t *>(entry);
	if (bytes[0] != 0x48 || bytes[1] != 0x85 || bytes[2] != 0xFF || bytes[3] != 0x0F || bytes[4] != 0x84) {
		return false;
	}
	int32_t displacement = 0;
	memcpy(&displacement, bytes + 5, sizeof(displacement));
	auto target = entry + NullPolicyPrefixSize + static_cast<mach_vm_address_t>(static_cast<int64_t>(displacement));
	if (target < address || target - address >= size) {
		return false;
	}
	return *reinterpret_cast<const uint8_t *>(target) == 0xC3;
}

void CoreTrustPolicy::wrapSetRootPolicy(const void *policy, void *certificate) {
	__atomic_fetch_add(&policyCalls, 1ULL, __ATOMIC_RELAXED);
	if (!policy) {
		__atomic_fetch_add(&nullPolicyCalls, 1ULL, __ATOMIC_RELAXED);
	}
	if (!policy && __atomic_load_n(&nativeNullPolicyNoOp, __ATOMIC_ACQUIRE)) {
		// Lilu copies this relative branch without relocating it. The validated
		// native NULL path only returns, so preserve that no-op here instead.
		__atomic_fetch_add(&nullPolicyNativeSkipped, 1ULL, __ATOMIC_RELAXED);
	} else {
		orgSetRootPolicy(policy, certificate);
	}
	// Additional anchors still receive their policy when native evaluation is a no-op.
	anchorRegistry.applyRootPolicy(static_cast<CoreTrust::Certificate *>(certificate));
}

void *CoreTrustPolicy::wrapFindRoot(const void *keyIdentifier, bool allowTestRoots) {
	__atomic_fetch_add(&lookupCalls, 1ULL, __ATOMIC_RELAXED);
	void *nativeRoot = orgFindRoot(keyIdentifier, allowTestRoots);
	if (nativeRoot) {
		return nativeRoot;
	}
	return anchorRegistry.findRoot(static_cast<const CoreTrust::OctetString *>(keyIdentifier));
}

mach_vm_address_t CoreTrustPolicy::getRouteTarget(mach_vm_address_t address) {
	if (!address) {
		return 0;
	}

	auto bytes = reinterpret_cast<const uint8_t *>(address);
	int32_t displacement = 0;
	if (bytes[0] == 0xE9) {
		memcpy(&displacement, bytes + 1, sizeof(displacement));
		return address + 5 + static_cast<mach_vm_address_t>(displacement);
	}
	if (bytes[0] == 0xFF && bytes[1] == 0x25) {
		memcpy(&displacement, bytes + 2, sizeof(displacement));
		mach_vm_address_t target = 0;
		auto slot = reinterpret_cast<const void *>(address + 6 + static_cast<mach_vm_address_t>(displacement));
		memcpy(&target, slot, sizeof(target));
		return target;
	}
	return 0;
}

void CoreTrustPolicy::publishProperties(OSDictionary *properties) {
	setDiagnosticNumber(properties, "InstallStatus", static_cast<uint32_t>(installStatus));
	setDiagnosticNumber(properties, "FlagsCalls", __atomic_load_n(&policyCalls, __ATOMIC_RELAXED));
	setDiagnosticNumber(properties, "LookupCalls", __atomic_load_n(&lookupCalls, __ATOMIC_RELAXED));
	setDiagnosticNumber(properties, "NullPolicyCalls", __atomic_load_n(&nullPolicyCalls, __ATOMIC_RELAXED));
	setDiagnosticNumber(
	    properties, "NullPolicyNativeSkipped", __atomic_load_n(&nullPolicyNativeSkipped, __ATOMIC_RELAXED)
	);
	setDiagnosticNumber(properties, "NativeNullPolicyNoOp", __atomic_load_n(&nativeNullPolicyNoOp, __ATOMIC_ACQUIRE));

	// These are observations, not evidence that an unknown later hook preserves
	// our callbacks. Signed controls and per-anchor counters establish coexistence.
	auto policyTarget = getRouteTarget(policyEntry);
	auto lookupTarget = getRouteTarget(lookupEntry);
	bool direct = policyTarget == reinterpret_cast<mach_vm_address_t>(wrapSetRootPolicy) &&
	              lookupTarget == reinterpret_cast<mach_vm_address_t>(wrapFindRoot);
	bool rerouted = policyTarget && lookupTarget &&
	                policyTarget != reinterpret_cast<mach_vm_address_t>(wrapSetRootPolicy) &&
	                lookupTarget != reinterpret_cast<mach_vm_address_t>(wrapFindRoot);
	setDiagnosticNumber(properties, "CoreTrustEntriesDirectToAMFIAnchor", direct);
	setDiagnosticNumber(properties, "CoreTrustEntriesReroutedLater", rerouted);
}
