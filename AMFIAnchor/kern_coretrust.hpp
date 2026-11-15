// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 b00t0x

#ifndef kern_coretrust_hpp
#define kern_coretrust_hpp

#include <Headers/kern_api.hpp>

class OSDictionary;

/**
 *  The private CoreTrust ABI used by the two root-selection hooks.
 *
 *  Recovered during compatibility analysis of AMFIPass 1.4.1 for Darwin 20-25.
 *  These offsets and policy bits are not a supported Apple API.
 *  See Docs/Design.md before extending support to another kernel generation.
 */
namespace CoreTrust {
struct OctetString {
	const uint8_t *data;
	size_t length;
};

struct Certificate {
	uint8_t reservedBeforePublicKey[0x58];
	OctetString publicKey;
	uint8_t reservedBeforeKeyIdentifier[0x50];
	OctetString subjectKeyIdentifier;
	uint8_t reservedBeforePolicy[0x28];
	uint64_t policyFlags;
	uint8_t reservedAfterPolicy[0x38];
};

static_assert(sizeof(Certificate) == 0x130, "CoreTrust certificate size changed");
static_assert(offsetof(Certificate, publicKey) == 0x58, "CoreTrust public-key offset changed");
static_assert(offsetof(Certificate, subjectKeyIdentifier) == 0xB8, "CoreTrust key-identifier offset changed");
static_assert(offsetof(Certificate, policyFlags) == 0xF0, "CoreTrust policy offset changed");

/** Root policy observed for the supported signing hierarchy, not a wildcard result. */
static constexpr uint64_t AdditionalRootPolicy {0xE30653FFF8ULL};
} // namespace CoreTrust

class CoreTrustPolicy {
public:
	/** Register the CoreTrust callback while the caller holds Lilu API access. */
	static LiluAPI::Error init();

	/** Allocate an on-demand diagnostic snapshot, outside the trust hooks. */
	static void publishProperties(OSDictionary *properties);

private:
	using PolicyFunction = void (*)(const void *, void *);
	using LookupFunction = void *(*)(const void *, bool);

	enum class InstallStatus : uint32_t { Pending = 0, Installed, PreexistingShortRoute, MissingSymbol, RoutingFailed };

	static PolicyFunction orgSetRootPolicy;
	static LookupFunction orgFindRoot;
	static mach_vm_address_t policyEntry;
	static mach_vm_address_t lookupEntry;
	static InstallStatus installStatus;
	static uint64_t policyCalls;
	static uint64_t lookupCalls;
	static uint64_t nullPolicyCalls;
	static uint64_t nullPolicyNativeSkipped;
	static bool nativeNullPolicyNoOp;
	static KernelPatcher::KextInfo coreTrust;

	static void processKext(void *user, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size);

	/** Recognise a native NULL branch that only returns, before replacing the entry. */
	static bool hasNullPolicyNoOp(mach_vm_address_t entry, mach_vm_address_t address, size_t size);

	/** Preserve native policy evaluation, including a validated NULL no-op, then match registered keys. */
	static void wrapSetRootPolicy(const void *policy, void *certificate);

	/** Preserve native root lookup and consult additional anchors only on a miss. */
	static void *wrapFindRoot(const void *keyIdentifier, bool allowTestRoots);

	static mach_vm_address_t getRouteTarget(mach_vm_address_t address);
};

#endif /* kern_coretrust_hpp */
