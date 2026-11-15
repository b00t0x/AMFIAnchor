// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 b00t0x

#ifndef kern_anchor_hpp
#define kern_anchor_hpp

#include <IOKit/IOLib.h>
#include <libkern/c++/OSDictionary.h>

#include "kern_coretrust.hpp"

class OSData;

class AnchorRegistry {
public:
	AnchorRegistry() = default;
	AnchorRegistry(const AnchorRegistry &) = delete;
	AnchorRegistry &operator=(const AnchorRegistry &) = delete;

	static constexpr unsigned MaxAnchors {16};
	static constexpr unsigned MaxPublicKeySize {1024};
	static constexpr unsigned KeyIdentifierSize {20};
	static constexpr unsigned MaxIdentifierSize {64};
	static constexpr uint64_t SchemaVersion {1};

	struct RegistrationResult {
		bool validConfiguration {false};
		unsigned accepted {0};
		unsigned rejected {0};
		unsigned disabled {0};
	};

	/** Allocate the sole writer lock before IOKit can start any provider. */
	bool init();

	/**
	 *  Copy valid anchors from a provider's IORegistry configuration.
	 *
	 *  Runs in provider start context, where allocation and locking are allowed.
	 *  Configuration objects are borrowed for this call only. Accepted key bytes,
	 *  identifiers, and certificates are owned by this registry until reboot.
	 *  Duplicate IDs, keys, and key identifiers are rejected rather than replaced.
	 */
	RegistrationResult registerProvider(OSDictionary *configuration, const char *providerIdentifier);

	/** No allocation or locks: amend policy only for a published public key. */
	bool applyRootPolicy(CoreTrust::Certificate *certificate);

	/** No allocation or locks: return a stable certificate after an identifier match. */
	CoreTrust::Certificate *findRoot(const CoreTrust::OctetString *keyIdentifier);

	/** Allocate an on-demand diagnostic snapshot; never called by a trust hook. */
	void publishProperties(OSDictionary *properties) const;

	static bool isValidIdentifier(const char *identifier);

private:
	struct Anchor {
		CoreTrust::Certificate certificate {};
		uint8_t publicKey[MaxPublicKeySize] {};
		uint8_t keyIdentifier[KeyIdentifierSize] {};
		char identifier[MaxIdentifierSize] {};
		char providerIdentifier[MaxIdentifierSize] {};
		uint64_t policyMatches {0};
		uint64_t lookupMatches {0};
	};

	Anchor anchors[MaxAnchors] {};
	IOLock *registrationLock {nullptr};

	/**
	 *  Writers hold registrationLock and publish this count with release ordering
	 *  only after a complete entry exists. Readers acquire it and never touch the
	 *  unpublished tail. Published key bytes and storage addresses never change.
	 */
	unsigned publishedCount {0};
	unsigned providerCount {0};
	unsigned rejectedCount {0};
	unsigned disabledCount {0};

	bool addAnchor(const char *identifier, const char *providerIdentifier, OSData *publicKey, OSData *keyIdentifier);
	bool hasConflict(
	    const char *identifier, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *keyIdentifier
	) const;
	static bool isValidPublicKey(const uint8_t *bytes, size_t size);
	static bool matches(const CoreTrust::OctetString *item, const uint8_t *bytes, size_t size);
};

/** Single boot-lifetime owner; the kext cannot be unloaded after hooks are installed. */
extern AnchorRegistry anchorRegistry;

/** Shared diagnostic helper. The dictionary retains the new number. */
void setDiagnosticNumber(OSDictionary *properties, const char *name, uint64_t value);

#endif /* kern_anchor_hpp */
