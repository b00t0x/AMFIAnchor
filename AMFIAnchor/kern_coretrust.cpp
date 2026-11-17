// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 b00t0x

#include "kern_coretrust.hpp"

#include "kern_anchor.hpp"

namespace {
const char *coreTrustPaths[] {"/System/Library/Extensions/CoreTrust.kext/Contents/MacOS/CoreTrust"};
}

CoreTrustPolicy::PolicyFunction CoreTrustPolicy::orgSetRootPolicy {nullptr};
CoreTrustPolicy::LookupFunction CoreTrustPolicy::orgFindRoot {nullptr};
CoreTrustPolicy::InstallStatus CoreTrustPolicy::installStatus {InstallStatus::Pending};
#if DEBUG
uint64_t CoreTrustPolicy::policyCalls {0};
uint64_t CoreTrustPolicy::lookupCalls {0};
uint64_t CoreTrustPolicy::nullPolicyCalls {0};
uint64_t CoreTrustPolicy::nullPolicyNativeSkipped {0};
#endif
bool CoreTrustPolicy::nativeNullPolicyNoOp {false};
KernelPatcher::KextInfo CoreTrustPolicy::coreTrust {
    "com.apple.kext.CoreTrust", coreTrustPaths, arrsize(coreTrustPaths), {true}, {}, 0
};

CoreTrustPolicy::InstallStatus CoreTrustPolicy::getInstallStatus() {
	InstallStatus status;
	__atomic_load(&installStatus, &status, __ATOMIC_RELAXED);
	return status;
}

void CoreTrustPolicy::setInstallStatus(InstallStatus status) {
	__atomic_store(&installStatus, &status, __ATOMIC_RELAXED);
}

void CoreTrustPolicy::init() {
	auto error = lilu.onKextLoad(&coreTrust, 1, processKext, nullptr);
	if (error != LiluAPI::Error::NoError) {
		// Lilu may already hold a callback pointer. Stay resident and inhibit it.
		setInstallStatus(InstallStatus::RegistrationFailed);
		SYSLOG("init", "CoreTrust callback registration failed, error %d", error);
	}
}

void CoreTrustPolicy::processKext(
    void *, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size
) {
	if (index != coreTrust.loadIndex || getInstallStatus() != InstallStatus::Pending) {
		return;
	}

	auto policyEntry = patcher.solveSymbol(index, "_X509PolicySetFlagsForRoots");
	auto lookupEntry = patcher.solveSymbol(index, "_X509ChainGetAppleRootUsingKeyIdentifier");
	if (!policyEntry || !lookupEntry) {
		setInstallStatus(InstallStatus::MissingSymbol);
		SYSLOG("policy", "missing CoreTrust root-selection symbols");
		patcher.clearError();
		return;
	}

	// A preexisting short route cannot be safely chained by Lilu. Keep both native
	// functions untouched in this case; placing AMFIAnchor first avoids this order.
	auto policyBytes = reinterpret_cast<const uint8_t *>(policyEntry);
	auto lookupBytes = reinterpret_cast<const uint8_t *>(lookupEntry);
	if (policyBytes[0] == 0xE9 || lookupBytes[0] == 0xE9) {
		setInstallStatus(InstallStatus::PreexistingShortRoute);
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
	setInstallStatus(routed ? InstallStatus::Installed : InstallStatus::RoutingFailed);
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
	// Lilu copies this relative branch without relocating it. The validated
	// native NULL path only returns, so preserve that no-op here instead.
	bool skipNative = !policy && __atomic_load_n(&nativeNullPolicyNoOp, __ATOMIC_ACQUIRE);
#if DEBUG
	__atomic_fetch_add(&policyCalls, 1ULL, __ATOMIC_RELAXED);
	if (!policy) {
		__atomic_fetch_add(&nullPolicyCalls, 1ULL, __ATOMIC_RELAXED);
	}
	if (skipNative) {
		__atomic_fetch_add(&nullPolicyNativeSkipped, 1ULL, __ATOMIC_RELAXED);
	}
#endif
	if (!skipNative) {
		orgSetRootPolicy(policy, certificate);
	}
	// Additional anchors still receive their policy when native evaluation is a no-op.
	anchorRegistry.applyRootPolicy(static_cast<CoreTrust::Certificate *>(certificate));
}

void *CoreTrustPolicy::wrapFindRoot(const void *keyIdentifier, bool allowTestRoots) {
#if DEBUG
	__atomic_fetch_add(&lookupCalls, 1ULL, __ATOMIC_RELAXED);
#endif
	void *nativeRoot = orgFindRoot(keyIdentifier, allowTestRoots);
	if (nativeRoot) {
		return nativeRoot;
	}
	return anchorRegistry.findRoot(static_cast<const CoreTrust::OctetString *>(keyIdentifier));
}

void CoreTrustPolicy::publishProperties(OSDictionary *properties) {
	setDiagnosticNumber(properties, "InstallStatus", static_cast<uint32_t>(getInstallStatus()));
#if DEBUG
	setDiagnosticNumber(properties, "FlagsCalls", __atomic_load_n(&policyCalls, __ATOMIC_RELAXED));
	setDiagnosticNumber(properties, "LookupCalls", __atomic_load_n(&lookupCalls, __ATOMIC_RELAXED));
	setDiagnosticNumber(properties, "NullPolicyCalls", __atomic_load_n(&nullPolicyCalls, __ATOMIC_RELAXED));
	setDiagnosticNumber(
	    properties, "NullPolicyNativeSkipped", __atomic_load_n(&nullPolicyNativeSkipped, __ATOMIC_RELAXED)
	);
	setDiagnosticNumber(properties, "NativeNullPolicyNoOp", __atomic_load_n(&nativeNullPolicyNoOp, __ATOMIC_ACQUIRE));
#endif
}
