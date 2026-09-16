// Copyright (c) 2026 System Locker. All rights reserved.

#include "NightflyerBlueprintLibrary.h"
#include "NightflyerSessionHolder.h"
#include "UnrealHttpTransport.h"

#include "syslocker/nightflyer.hpp"

#include "Async/Async.h"
#include "HAL/PlatformFile.h"
#include "HAL/PlatformFileManager.h"
#include "Misc/Paths.h"

#include <cctype>
#include <memory>

namespace
{
    using namespace syslocker::nightflyer;

    syslocker::nightflyer::Config toConfig(const FNightflyerSettings& settings)
    {
        Config config;
        const auto timeoutSeconds = FMath::Clamp(settings.RequestTimeoutSeconds, 1, 3600);
        config.systemId = TCHAR_TO_UTF8(*settings.SystemId);
        config.baseUrl = TCHAR_TO_UTF8(*settings.BaseUrl);
        config.expectedIssuer = TCHAR_TO_UTF8(*settings.ExpectedIssuer);
        config.sdkVersion = "0.2.0";
        config.timeout = std::chrono::seconds(timeoutSeconds);
        config.idempotentTransportRetries = FMath::Clamp(settings.IdempotentRetries, 0, 5);
        config.requireOnlineAfterReboot = settings.RequireOnlineAfterReboot;
        for (const auto& pair : settings.TrustedSigningKeys)
        {
            config.trustedSigningKeys.emplace(TCHAR_TO_UTF8(*pair.Key), TCHAR_TO_UTF8(*pair.Value));
        }
        return config;
    }

    ENightflyerAuthorizationState toState(AuthorizationState state)
    {
        switch (state)
        {
        case AuthorizationState::authorized_online: return ENightflyerAuthorizationState::AuthorizedOnline;
        case AuthorizationState::authorized_offline: return ENightflyerAuthorizationState::AuthorizedOffline;
        case AuthorizationState::renewal_due: return ENightflyerAuthorizationState::RenewalDue;
        case AuthorizationState::expired: return ENightflyerAuthorizationState::Expired;
        case AuthorizationState::ending: return ENightflyerAuthorizationState::Ending;
        case AuthorizationState::ended: return ENightflyerAuthorizationState::Ended;
        case AuthorizationState::inactive: return ENightflyerAuthorizationState::Inactive;
        case AuthorizationState::auth_mode_in_use: return ENightflyerAuthorizationState::AuthModeInUse;
        case AuthorizationState::protocol_upgrade_required: return ENightflyerAuthorizationState::ProtocolUpgradeRequired;
        case AuthorizationState::clock_untrusted: return ENightflyerAuthorizationState::ClockUntrusted;
        case AuthorizationState::device_changed: return ENightflyerAuthorizationState::DeviceChanged;
        case AuthorizationState::auth_denied: return ENightflyerAuthorizationState::AuthDenied;
        case AuthorizationState::storage_unavailable: return ENightflyerAuthorizationState::StorageUnavailable;
        case AuthorizationState::network_unavailable: return ENightflyerAuthorizationState::NetworkUnavailable;
        case AuthorizationState::protocol_failure: return ENightflyerAuthorizationState::ProtocolFailure;
        case AuthorizationState::installation_in_use: return ENightflyerAuthorizationState::InstallationInUse;
        }
        return ENightflyerAuthorizationState::AuthDenied;
    }

    ENightflyerRecommendedAction toAction(EasyAuthorizationAction action)
    {
        switch (action)
        {
        case EasyAuthorizationAction::none: return ENightflyerRecommendedAction::None;
        case EasyAuthorizationAction::continue_offline: return ENightflyerRecommendedAction::ContinueOffline;
        case EasyAuthorizationAction::retry_online: return ENightflyerRecommendedAction::RetryOnline;
        case EasyAuthorizationAction::request_license_key: return ENightflyerRecommendedAction::RequestLicenseKey;
        case EasyAuthorizationAction::update_client: return ENightflyerRecommendedAction::UpdateClient;
        case EasyAuthorizationAction::check_clock: return ENightflyerRecommendedAction::CheckClock;
        case EasyAuthorizationAction::repair_protected_storage: return ENightflyerRecommendedAction::RepairProtectedStorage;
        case EasyAuthorizationAction::resolve_device_binding: return ENightflyerRecommendedAction::ResolveDeviceBinding;
        case EasyAuthorizationAction::resolve_authentication_mode: return ENightflyerRecommendedAction::ResolveAuthenticationMode;
        case EasyAuthorizationAction::wait_for_installation: return ENightflyerRecommendedAction::WaitForInstallation;
        case EasyAuthorizationAction::contact_developer: return ENightflyerRecommendedAction::ContactDeveloper;
        }
        return ENightflyerRecommendedAction::ContactDeveloper;
    }

    EasyAuthorizationAction actionForState(AuthorizationState state)
    {
        switch (state)
        {
        case AuthorizationState::authorized_online: return EasyAuthorizationAction::none;
        case AuthorizationState::authorized_offline: return EasyAuthorizationAction::continue_offline;
        case AuthorizationState::renewal_due:
        case AuthorizationState::network_unavailable:
        case AuthorizationState::ending: return EasyAuthorizationAction::retry_online;
        case AuthorizationState::inactive:
        case AuthorizationState::ended:
        case AuthorizationState::expired:
        case AuthorizationState::auth_denied: return EasyAuthorizationAction::request_license_key;
        case AuthorizationState::protocol_upgrade_required: return EasyAuthorizationAction::update_client;
        case AuthorizationState::clock_untrusted: return EasyAuthorizationAction::check_clock;
        case AuthorizationState::storage_unavailable: return EasyAuthorizationAction::repair_protected_storage;
        case AuthorizationState::device_changed: return EasyAuthorizationAction::resolve_device_binding;
        case AuthorizationState::auth_mode_in_use: return EasyAuthorizationAction::resolve_authentication_mode;
        case AuthorizationState::installation_in_use: return EasyAuthorizationAction::wait_for_installation;
        default: return EasyAuthorizationAction::contact_developer;
        }
    }

    void applySnapshot(FNightflyerAuthorizationResult& result, const AuthorizationSnapshot& snapshot)
    {
        const auto action = actionForState(snapshot.state);
        result.State = toState(snapshot.state);
        result.CanProceed = snapshot.lease.has_value();
        result.IsOffline = result.CanProceed && snapshot.state != AuthorizationState::authorized_online;
        result.ShouldPromptForKey = action == EasyAuthorizationAction::request_license_key;
        result.RecommendedAction = toAction(action);
        result.LeaseExpiresAtUtc = snapshot.lease ? static_cast<int64>(snapshot.lease->expiresAt) : 0;
        result.LeaseRenewAfterUtc = snapshot.lease ? static_cast<int64>(snapshot.lease->renewAfter) : 0;
        result.Diagnostic = UTF8_TO_TCHAR(snapshot.diagnostic.c_str());
    }

    bool validSystemId(std::string_view value)
    {
        if (value.size() != 20) return false;
        for (const unsigned char character : value)
        {
            if (!((character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9'))) return false;
        }
        return true;
    }

    AuthorizationSession createSession(
        const Config& config,
        bool persistent,
        const std::shared_ptr<IHttpClient>& transport)
    {
        // Validate before deriving a state path or key name from project input.
        if (!validSystemId(config.systemId))
            throw syslocker::nightflyer::Error(Failure::configuration, "System ID must contain exactly 20 ASCII alphanumeric characters.");

        if (!persistent) return AuthorizationSession::memory(config, transport);

#if PLATFORM_WINDOWS
        const auto directory = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("SystemLockerNightflyer"));
        if (!FPlatformFileManager::Get().GetPlatformFile().CreateDirectoryTree(*directory))
            throw syslocker::nightflyer::Error(Failure::local_failure, "The Nightflyer state directory could not be created.");
        const auto fileName = FString(UTF8_TO_TCHAR(config.systemId.c_str())) + TEXT(".bin");
        const auto path = FPaths::Combine(directory, fileName);
        return AuthorizationSession::persistent(
            config,
            makeWindowsDpapiStateStore(TCHAR_TO_UTF8(*path)),
            transport);
#elif PLATFORM_MAC
        return AuthorizationSession::persistent(
            config,
            makeMacosKeychainStateStore("com.systemlocker.nightflyer", config.systemId),
            makeMacosKeychainInstallationKeyProvider(),
            transport);
#else
        throw syslocker::nightflyer::Error(
            Failure::configuration,
            "Blueprint persistent sessions require Windows or macOS; use the C++ API to provide protected Linux storage.");
#endif
    }

    AuthorizationSession& sessionFor(
        UNightflyerSessionHolder* owner,
        const Config& config,
        bool persistent,
        const std::shared_ptr<IHttpClient>& transport)
    {
        auto& slot = owner->Sessions[config.systemId];
        if (!slot.Matches(config, persistent))
        {
            // Reset first: memory sessions own a per-installation lock until
            // destruction and must release it before their replacement opens.
            slot.Session.reset();
            slot.Session.emplace(createSession(config, persistent, transport));
            slot.Remember(config, persistent);
        }
        return *slot.Session;
    }

    /** Root'ed, GC-safe owner of the native session (NightflyerSessionHolder.h). */
    UNightflyerSessionHolder* sessionHolder() { return UNightflyerSessionHolder::Acquire(); }
}

void UNightflyerBlueprintLibrary::EasyAuthorize(UObject* WorldContextObject, const FNightflyerSettings& Settings, const FNightflyerBinding& Binding, int32 RequestedOfflineSeconds, const FString& LicenseKey, bool Persistent, FNightflyerAuthorizationDelegate OnComplete)
{
    (void)WorldContextObject;
    const auto owner = sessionHolder();
    const auto config = toConfig(Settings);
    const syslocker::nightflyer::Binding binding{
        TCHAR_TO_UTF8(*Binding.Version),
        TCHAR_TO_UTF8(*Binding.ProgramDigest),
        TCHAR_TO_UTF8(*Binding.SlHwid)};
    const auto enteredKey = LicenseKey.IsEmpty() ? std::optional<std::string>{} : std::optional<std::string>{TCHAR_TO_UTF8(*LicenseKey)};
    const auto timeoutSeconds = FMath::Clamp(Settings.RequestTimeoutSeconds, 1, 3600);
    const auto transport = makeUnrealHttpTransport(std::chrono::seconds(timeoutSeconds));

    Async(EAsyncExecution::ThreadPool, [owner, config, binding, RequestedOfflineSeconds, enteredKey, Persistent, transport, OnComplete]()
    {
        FNightflyerAuthorizationResult result;
        try
        {
            std::lock_guard<std::mutex> lock(owner->Gate);
            const auto outcome = sessionFor(owner, config, Persistent, transport)
                .easyAuthorize(binding, RequestedOfflineSeconds, enteredKey);
            result.State = toState(outcome.snapshot.state);
            result.CanProceed = outcome.canProceed;
            result.IsOffline = outcome.isOffline;
            result.CredentialPresent = outcome.credentialPresent;
            result.ShouldPromptForKey = outcome.shouldPromptForKey;
            result.RecommendedAction = toAction(outcome.recommendedAction);
            result.RetryAfterSeconds = outcome.retryAfter ? static_cast<int32>(outcome.retryAfter->count()) : 0;
            result.LeaseExpiresAtUtc = outcome.snapshot.lease ? static_cast<int64>(outcome.snapshot.lease->expiresAt) : 0;
            result.LeaseRenewAfterUtc = outcome.snapshot.lease ? static_cast<int64>(outcome.snapshot.lease->renewAfter) : 0;
            result.Diagnostic = UTF8_TO_TCHAR(outcome.snapshot.diagnostic.c_str());
        }
        catch (const std::exception& error)
        {
            result.State = ENightflyerAuthorizationState::ProtocolFailure;
            result.Diagnostic = UTF8_TO_TCHAR(error.what());
        }

        AsyncTask(ENamedThreads::GameThread, [OnComplete, result]() { OnComplete.ExecuteIfBound(result); });
    });
}

void UNightflyerBlueprintLibrary::TickSession(UObject* WorldContextObject, const FNightflyerSettings& Settings, const FNightflyerBinding& Binding, FNightflyerAuthorizationDelegate OnComplete)
{
    (void)WorldContextObject;
    const auto owner = sessionHolder();
    const auto systemId = std::string(TCHAR_TO_UTF8(*Settings.SystemId));
    const syslocker::nightflyer::Binding binding{
        TCHAR_TO_UTF8(*Binding.Version),
        TCHAR_TO_UTF8(*Binding.ProgramDigest),
        TCHAR_TO_UTF8(*Binding.SlHwid)};

    Async(EAsyncExecution::ThreadPool, [owner, systemId, binding, OnComplete]()
    {
        FNightflyerAuthorizationResult result;
        try
        {
            std::lock_guard<std::mutex> lock(owner->Gate);
            const auto slot = owner->Sessions.find(systemId);
            if (slot != owner->Sessions.end() && slot->second.Session.has_value())
            {
                applySnapshot(result, slot->second.Session->tick(binding));
            }
            else
            {
                result.State = ENightflyerAuthorizationState::AuthDenied;
                result.ShouldPromptForKey = true;
                result.RecommendedAction = ENightflyerRecommendedAction::RequestLicenseKey;
                result.Diagnostic = TEXT("No Nightflyer session exists for this system.");
            }
        }
        catch (const std::exception& error)
        {
            result.State = ENightflyerAuthorizationState::ProtocolFailure;
            result.Diagnostic = UTF8_TO_TCHAR(error.what());
        }
        AsyncTask(ENamedThreads::GameThread, [OnComplete, result]() { OnComplete.ExecuteIfBound(result); });
    });
}

void UNightflyerBlueprintLibrary::EndSession(UObject* WorldContextObject, const FNightflyerSettings& Settings, FNightflyerAuthorizationDelegate OnComplete)
{
    (void)WorldContextObject;
    const auto owner = sessionHolder();
    const auto systemId = std::string(TCHAR_TO_UTF8(*Settings.SystemId));

    Async(EAsyncExecution::ThreadPool, [owner, systemId, OnComplete]()
    {
        FNightflyerAuthorizationResult result;
        try
        {
            std::lock_guard<std::mutex> lock(owner->Gate);
            const auto slot = owner->Sessions.find(systemId);
            if (slot != owner->Sessions.end() && slot->second.Session.has_value())
            {
                applySnapshot(result, slot->second.Session->end("game_shutdown"));
            }
            else
            {
                result.State = ENightflyerAuthorizationState::Ended;
                result.RecommendedAction = ENightflyerRecommendedAction::None;
                result.Diagnostic = TEXT("No active Nightflyer session exists for this system.");
            }
        }
        catch (const std::exception& error)
        {
            result.State = ENightflyerAuthorizationState::ProtocolFailure;
            result.Diagnostic = UTF8_TO_TCHAR(error.what());
        }
        AsyncTask(ENamedThreads::GameThread, [OnComplete, result]() { OnComplete.ExecuteIfBound(result); });
    });
}

void UNightflyerBlueprintLibrary::ForgetInstallation(UObject* WorldContextObject, const FNightflyerSettings& Settings)
{
    (void)WorldContextObject;
    const auto owner = sessionHolder();
    const auto systemId = std::string(TCHAR_TO_UTF8(*Settings.SystemId));
    Async(EAsyncExecution::ThreadPool, [owner, systemId]()
    {
        std::lock_guard<std::mutex> lock(owner->Gate);
        const auto slot = owner->Sessions.find(systemId);
        if (slot != owner->Sessions.end() && slot->second.Session.has_value())
        {
            try
            {
                slot->second.Session->forget();
                owner->Sessions.erase(slot);
            }
            catch (const std::exception&) {}
        }
    });
}
