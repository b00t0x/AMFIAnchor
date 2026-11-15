// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 b00t0x

#include <IOKit/IOService.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSSerialize.h>
#include <libkern/c++/OSString.h>

#include "kern_anchor.hpp"
#include "kern_coretrust.hpp"

bool ADDPR(debugEnabled) = false;
uint32_t ADDPR(debugPrintDelay) = 0;

/** Resource service exposing allocation-permitted, on-demand diagnostic snapshots. */
class AMFIAnchor : public IOService {
	OSDeclareDefaultStructors(AMFIAnchor)

public:
	bool start(IOService *provider) override;
	bool serializeProperties(OSSerialize *serializer) const override;
};

/** One instance per codeless injector, matched independently on IOResources. */
class AMFIAnchorProvider : public IOService {
	OSDeclareDefaultStructors(AMFIAnchorProvider)

public:
	bool start(IOService *provider) override;
};

OSDefineMetaClassAndStructors(AMFIAnchor, IOService)
OSDefineMetaClassAndStructors(AMFIAnchorProvider, IOService)

bool AMFIAnchor::start(IOService *provider) {
	if (!IOService::start(provider)) {
		return false;
	}
	setProperty("Version", xStringify(MODULE_VERSION));
	setProperty("ProviderSchemaVersion", AnchorRegistry::SchemaVersion, 64);
	return true;
}

bool AMFIAnchor::serializeProperties(OSSerialize *serializer) const {
	auto properties = dictionaryWithProperties();
	if (!properties) {
		return false;
	}
	anchorRegistry.publishProperties(properties);
	CoreTrustPolicy::publishProperties(properties);
	bool serialized = properties->serialize(serializer);
	properties->release();
	return serialized;
}

bool AMFIAnchorProvider::start(IOService *provider) {
	if (!IOService::start(provider)) {
		return false;
	}

	auto identifier = OSDynamicCast(OSString, getProperty("AMFIAnchorProviderID"));
	auto configuration = OSDynamicCast(OSDictionary, getProperty("AMFIAnchorConfig"));
	AnchorRegistry::RegistrationResult result;
	if (identifier) {
		result = anchorRegistry.registerProvider(configuration, identifier->getCStringNoCopy());
	}

	setProperty("AnchorRegistrationStatus", result.validConfiguration ? 1U : 2U, 32);
	setProperty("RegisteredAnchorCount", result.accepted, 32);
	setProperty("RejectedAnchorCount", result.rejected, 32);
	setProperty("DisabledAnchorCount", result.disabled, 32);
	DBGLOG(
	    "provider", "registered %u anchors, rejected %u, disabled %u", result.accepted, result.rejected, result.disabled
	);
	registerService();
	return true;
}

/**
 *  Register directly at module entry, before a later AMFIPass module can register
 *  its own CoreTrust callback. No boot-argument mutation or stock-private lookup
 *  is involved. The narrow kernel guard deliberately has no beta override.
 */
extern "C" kern_return_t anchorStart(kmod_info_t *, void *) {
	auto error = lilu.requestAccess();
	if (error != LiluAPI::Error::NoError) {
		SYSLOG("init", "Lilu access failed, error %d", error);
		return KERN_FAILURE;
	}

	if (getKernelVersion() < KernelVersion::BigSur || getKernelVersion() > KernelVersion::Tahoe ||
	    !anchorRegistry.init()) {
		SYSLOG("init", "unsupported kernel or anchor registry allocation failure");
		lilu.releaseAccess();
		return KERN_FAILURE;
	}

	error = CoreTrustPolicy::init();
	lilu.releaseAccess();
	if (error != LiluAPI::Error::NoError) {
		SYSLOG("init", "CoreTrust callback registration failed, error %d", error);
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

extern "C" kern_return_t anchorStop(kmod_info_t *, void *) {
	// CoreTrust can retain pointers into our boot-lifetime certificate table.
	return KERN_FAILURE;
}

extern "C" {
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
KMOD_EXPLICIT_DECL(org.b00t0x.AMFIAnchor, xStringify(MODULE_VERSION), _start, _stop)
__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain = anchorStart;
__attribute__((visibility("hidden"))) kmod_stop_func_t *_antimain = anchorStop;
__attribute__((visibility("hidden"))) int _kext_apple_cc = __APPLE_CC__;
}
