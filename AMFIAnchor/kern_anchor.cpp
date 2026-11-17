// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 b00t0x

#include "kern_anchor.hpp"

#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>

AnchorRegistry anchorRegistry;

namespace {
/** Read one bounded DER item and advance offset only within the supplied span. */
bool readDerItem(
    const uint8_t *bytes, size_t size, size_t &offset, uint8_t expectedTag, const uint8_t *&value, size_t &valueSize
) {
	if (offset >= size || bytes[offset++] != expectedTag || offset >= size) {
		return false;
	}

	unsigned lengthByte = bytes[offset++];
	valueSize = lengthByte;
	if (lengthByte & 0x80) {
		unsigned lengthBytes = lengthByte & 0x7F;
		if (lengthBytes == 0 || lengthBytes > 2 || lengthBytes > size - offset || bytes[offset] == 0) {
			return false;
		}

		valueSize = 0;
		for (unsigned index = 0; index < lengthBytes; index++) {
			valueSize = (valueSize << 8) | bytes[offset++];
		}
		if (valueSize < 128) {
			return false;
		}
	}

	if (valueSize > size - offset) {
		return false;
	}
	value = bytes + offset;
	offset += valueSize;
	return true;
}
} // namespace

void setDiagnosticNumber(OSDictionary *properties, const char *name, uint64_t value) {
	auto number = OSNumber::withNumber(value, 64);
	if (number) {
		properties->setObject(name, number);
		number->release();
	}
}

bool AnchorRegistry::init() {
	registrationLock = IOLockAlloc();
	return registrationLock != nullptr;
}

bool AnchorRegistry::isValidIdentifier(const char *identifier) {
	if (!identifier || identifier[0] == '\0') {
		return false;
	}

	unsigned length = 0;
	for (; length < MaxIdentifierSize && identifier[length] != '\0'; length++) {
		char character = identifier[length];
		bool valid = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
		             (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.';
		if (!valid) {
			return false;
		}
	}
	return length < MaxIdentifierSize;
}

bool AnchorRegistry::isValidPublicKey(const uint8_t *bytes, size_t size) {
	if (!bytes || size < 64 || size > MaxPublicKeySize) {
		return false;
	}

	// This checks SPKI structure and bounds, not the signature or certificate chain.
	size_t offset = 0;
	size_t sequenceSize = 0;
	const uint8_t *sequence = nullptr;
	if (!readDerItem(bytes, size, offset, 0x30, sequence, sequenceSize) || offset != size) {
		return false;
	}

	size_t sequenceOffset = 0;
	size_t algorithmSize = 0;
	const uint8_t *algorithm = nullptr;
	if (!readDerItem(sequence, sequenceSize, sequenceOffset, 0x30, algorithm, algorithmSize)) {
		return false;
	}

	size_t algorithmOffset = 0;
	size_t identifierSize = 0;
	const uint8_t *identifier = nullptr;
	if (!readDerItem(algorithm, algorithmSize, algorithmOffset, 0x06, identifier, identifierSize) ||
	    identifierSize == 0) {
		return false;
	}

	size_t bitStringSize = 0;
	const uint8_t *bitString = nullptr;
	return readDerItem(sequence, sequenceSize, sequenceOffset, 0x03, bitString, bitStringSize) &&
	       sequenceOffset == sequenceSize && bitStringSize > 32 && bitString[0] == 0;
}

bool AnchorRegistry::matches(const CoreTrust::OctetString *item, const uint8_t *bytes, size_t size) {
	return item && item->data && item->length == size && memcmp(item->data, bytes, size) == 0;
}

bool AnchorRegistry::hasConflict(
    const char *identifier, const uint8_t *publicKey, size_t publicKeySize, const uint8_t *keyIdentifier
) const {
	// Only registration calls this function, with the writer lock already held.
	unsigned count = __atomic_load_n(&publishedCount, __ATOMIC_RELAXED);
	for (unsigned index = 0; index < count; index++) {
		const auto &anchor = anchors[index];
		if (strcmp(identifier, anchor.identifier) == 0 ||
		    memcmp(keyIdentifier, anchor.keyIdentifier, KeyIdentifierSize) == 0 ||
		    matches(&anchor.certificate.publicKey, publicKey, publicKeySize)) {
			return true;
		}
	}
	return false;
}

bool AnchorRegistry::addAnchor(
    const char *identifier, const char *providerIdentifier, OSData *publicKey, OSData *keyIdentifier
) {
	unsigned count = __atomic_load_n(&publishedCount, __ATOMIC_RELAXED);
	if (!isValidIdentifier(identifier) || !publicKey || !keyIdentifier ||
	    keyIdentifier->getLength() != KeyIdentifierSize || count >= MaxAnchors) {
		return false;
	}

	auto keyBytes = static_cast<const uint8_t *>(publicKey->getBytesNoCopy());
	auto identifierBytes = static_cast<const uint8_t *>(keyIdentifier->getBytesNoCopy());
	static const uint8_t EmptyKeyIdentifier[KeyIdentifierSize] {};
	if (!isValidPublicKey(keyBytes, publicKey->getLength()) || !identifierBytes ||
	    memcmp(identifierBytes, EmptyKeyIdentifier, KeyIdentifierSize) == 0 ||
	    hasConflict(identifier, keyBytes, publicKey->getLength(), identifierBytes)) {
		return false;
	}

	auto &anchor = anchors[count];
	memcpy(anchor.identifier, identifier, strlen(identifier) + 1);
	memcpy(anchor.providerIdentifier, providerIdentifier, strlen(providerIdentifier) + 1);
	memcpy(anchor.publicKey, keyBytes, publicKey->getLength());
	memcpy(anchor.keyIdentifier, identifierBytes, KeyIdentifierSize);
	anchor.certificate.publicKey = {anchor.publicKey, publicKey->getLength()};
	anchor.certificate.subjectKeyIdentifier = {anchor.keyIdentifier, KeyIdentifierSize};
	anchor.certificate.policyFlags = CoreTrust::AdditionalRootPolicy;

	// Readers must never observe an entry with incomplete backing bytes or pointers.
	__atomic_store_n(&publishedCount, count + 1, __ATOMIC_RELEASE);
	return true;
}

AnchorRegistry::RegistrationResult
AnchorRegistry::registerProvider(OSDictionary *configuration, const char *providerIdentifier) {
	RegistrationResult result;
	auto schema = configuration ? OSDynamicCast(OSNumber, configuration->getObject("SchemaVersion")) : nullptr;
	auto entries = configuration ? OSDynamicCast(OSDictionary, configuration->getObject("Anchors")) : nullptr;
	static constexpr unsigned MaxConfigurationEntries {64};
	if (!registrationLock || !isValidIdentifier(providerIdentifier) || !schema ||
	    schema->unsigned64BitValue() != SchemaVersion || !entries || entries->getCount() > MaxConfigurationEntries) {
		return result;
	}

	auto iterator = OSCollectionIterator::withCollection(entries);
	if (!iterator) {
		return result;
	}

	IOLockLock(registrationLock);
	while (auto key = iterator->getNextObject()) {
		auto identifier = OSDynamicCast(OSString, key);
		auto entry = identifier ? OSDynamicCast(OSDictionary, entries->getObject(identifier)) : nullptr;
		if (!entry) {
			result.rejected++;
			continue;
		}

		auto enabled = entry->getObject("Enabled");
		if (enabled && !OSDynamicCast(OSBoolean, enabled)) {
			result.rejected++;
			continue;
		}
		if (enabled == kOSBooleanFalse) {
			result.disabled++;
			continue;
		}

		auto publicKey = OSDynamicCast(OSData, entry->getObject("SPKI"));
		auto keyIdentifier = OSDynamicCast(OSData, entry->getObject("SKID"));
		if (addAnchor(identifier->getCStringNoCopy(), providerIdentifier, publicKey, keyIdentifier)) {
			result.accepted++;
		} else {
			result.rejected++;
		}
	}

	__atomic_fetch_add(&providerCount, 1U, __ATOMIC_RELEASE);
	__atomic_fetch_add(&rejectedCount, result.rejected, __ATOMIC_RELAXED);
	__atomic_fetch_add(&disabledCount, result.disabled, __ATOMIC_RELAXED);
	IOLockUnlock(registrationLock);
	iterator->release();
	result.validConfiguration = true;
	return result;
}

bool AnchorRegistry::applyRootPolicy(CoreTrust::Certificate *certificate) {
	if (!certificate) {
		return false;
	}

	unsigned count = __atomic_load_n(&publishedCount, __ATOMIC_ACQUIRE);
	for (unsigned index = 0; index < count; index++) {
		auto &anchor = anchors[index];
		if (matches(&certificate->publicKey, anchor.publicKey, anchor.certificate.publicKey.length)) {
#if DEBUG
			__atomic_fetch_add(&anchor.policyMatches, 1ULL, __ATOMIC_RELAXED);
#endif
			certificate->policyFlags = CoreTrust::AdditionalRootPolicy;
			return true;
		}
	}
	return false;
}

CoreTrust::Certificate *AnchorRegistry::findRoot(const CoreTrust::OctetString *keyIdentifier) {
	unsigned count = __atomic_load_n(&publishedCount, __ATOMIC_ACQUIRE);
	for (unsigned index = 0; index < count; index++) {
		auto &anchor = anchors[index];
		if (matches(keyIdentifier, anchor.keyIdentifier, KeyIdentifierSize)) {
#if DEBUG
			__atomic_fetch_add(&anchor.lookupMatches, 1ULL, __ATOMIC_RELAXED);
#endif
			return &anchor.certificate;
		}
	}
	return nullptr;
}

void AnchorRegistry::publishProperties(OSDictionary *properties) const {
	unsigned count = __atomic_load_n(&publishedCount, __ATOMIC_ACQUIRE);
	setDiagnosticNumber(properties, "AnchorCount", count);
	setDiagnosticNumber(properties, "AnchorReady", count > 0);
	setDiagnosticNumber(properties, "ProviderCount", __atomic_load_n(&providerCount, __ATOMIC_ACQUIRE));
	setDiagnosticNumber(properties, "RejectedAnchors", __atomic_load_n(&rejectedCount, __ATOMIC_RELAXED));
	setDiagnosticNumber(properties, "DisabledAnchors", __atomic_load_n(&disabledCount, __ATOMIC_RELAXED));

	auto list = OSArray::withCapacity(count);
	if (!list) {
		return;
	}

	for (unsigned index = 0; index < count; index++) {
		const auto &anchor = anchors[index];
		auto row = OSDictionary::withCapacity(DEBUG ? 5 : 3);
		auto identifier = OSString::withCString(anchor.identifier);
		auto provider = OSString::withCString(anchor.providerIdentifier);
		if (row && identifier && provider) {
			row->setObject("Identifier", identifier);
			row->setObject("Provider", provider);
			setDiagnosticNumber(row, "SPKIBytes", anchor.certificate.publicKey.length);
#if DEBUG
			setDiagnosticNumber(row, "FlagsMatches", __atomic_load_n(&anchor.policyMatches, __ATOMIC_RELAXED));
			setDiagnosticNumber(row, "LookupMatches", __atomic_load_n(&anchor.lookupMatches, __ATOMIC_RELAXED));
#endif
			list->setObject(row);
		}
		if (identifier) {
			identifier->release();
		}
		if (provider) {
			provider->release();
		}
		if (row) {
			row->release();
		}
	}
	properties->setObject("LoadedAnchors", list);
	list->release();
}
