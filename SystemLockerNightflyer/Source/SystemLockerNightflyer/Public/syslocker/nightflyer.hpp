// Copyright (c) 2026 System Locker. All rights reserved.

#pragma once

// UnrealBuildTool supplies SYSTEMLOCKERNIGHTFLYER_API as DLLEXPORT/DLLIMPORT.
// Pull in the platform definition when this header is compiled by Unreal;
// standalone conformance builds intentionally remain engine-independent.
#if defined(UE_GAME) || defined(UE_EDITOR)
#include "HAL/Platform.h"
#endif

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifndef SYSTEMLOCKERNIGHTFLYER_API
#define SYSTEMLOCKERNIGHTFLYER_API
#endif

namespace syslocker::nightflyer
{
    enum class Failure { configuration, transport, invalid_response, invalid_signature, invalid_token, invalid_state, local_failure };

    class SYSTEMLOCKERNIGHTFLYER_API Error final : public std::runtime_error
    {
    public:
        Error(Failure failure, std::string message, std::optional<long> httpStatus = {}, std::optional<std::chrono::seconds> retryAfter = {});
        Failure failure() const noexcept { return failure_; }
        std::optional<long> httpStatus() const noexcept { return httpStatus_; }
        std::optional<std::chrono::seconds> retryAfter() const noexcept { return retryAfter_; }
    private:
        Failure failure_;
        std::optional<long> httpStatus_;
        std::optional<std::chrono::seconds> retryAfter_;
    };

    class IClock
    {
    public:
        virtual ~IClock() = default;
        virtual std::int64_t unixSeconds() const = 0;
        virtual std::int64_t monotonicMilliseconds() const = 0;
        virtual std::string bootIdentifier() const = 0;
    };
    SYSTEMLOCKERNIGHTFLYER_API std::shared_ptr<IClock> systemClock();

    struct Config
    {
        std::string systemId;
        std::string baseUrl = "https://systemlocker.net";
        std::string expectedIssuer = "https://systemlocker.net";
        std::string sdkVersion = "0.2.0";
        std::chrono::milliseconds timeout{15000};
        int idempotentTransportRetries = 1;
        std::chrono::milliseconds installationLockTimeout{5000};
        // Optional stricter policy for deployments that prefer additional
        // snapshot-replay resistance over offline availability after reboot.
        // The default still rejects UTC rollback behind the signed high-water
        // checkpoint.
        bool requireOnlineAfterReboot = false;
        std::shared_ptr<IClock> clock = systemClock();
        std::map<std::string, std::string> trustedSigningKeys;
    };

    struct HttpResponse
    {
        long status = 0;
        std::string body;
        std::string error;
        std::map<std::string, std::string> headers;
        SYSTEMLOCKERNIGHTFLYER_API std::optional<std::chrono::seconds> retryAfter() const;
    };

    /// Synchronous HTTPS POST seam. The engine transport (UnrealHttpTransport.h)
    /// implements it over the engine's HTTP module.
    /// Implementations must enforce certificate validation, refuse redirects,
    /// cap response bodies at 1 MiB, and report failures through HttpResponse::error.
    class IHttpClient
    {
    public:
        virtual ~IHttpClient() = default;
        virtual HttpResponse postJson(std::string_view url, std::string_view body, std::string_view proof) = 0;
    };

    class SYSTEMLOCKERNIGHTFLYER_API InstallationKey
    {
    public:
        struct Impl;
        static InstallationKey ephemeral();
        /// Imports a P-256 private scalar (base64url, 32 bytes) previously
        /// exported with toPrivateKey. Adapter authors are responsible for
        /// protecting the material they persist.
        static InstallationKey fromPrivateKey(std::string_view encoded);
        explicit InstallationKey(std::unique_ptr<Impl> impl);
        ~InstallationKey();
        InstallationKey(InstallationKey&&) noexcept;
        InstallationKey& operator=(InstallationKey&&) noexcept;
        InstallationKey(const InstallationKey&) = delete;
        InstallationKey& operator=(const InstallationKey&) = delete;
        std::string publicJwk() const;
        std::string thumbprint() const;
        /// base64url of the 32-byte P-256 private scalar; handle as a secret.
        std::string toPrivateKey() const;
    private:
        std::unique_ptr<Impl> impl_;
        friend class Client;
    };

    struct InstallationKeyHandle
    {
        std::string reference;
        InstallationKey key;
    };

    class IInstallationKeyProvider
    {
    public:
        virtual ~IInstallationKeyProvider() = default;
        virtual InstallationKeyHandle create(std::string_view systemId) = 0;
        virtual InstallationKeyHandle load(std::string_view systemId, std::string_view reference) = 0;
        virtual InstallationKeyHandle openOrCreateStable(std::string_view systemId) = 0;
        virtual void erase(std::string_view systemId, std::string_view reference) = 0;
    };
    /// Windows: non-exportable CNG keys in the Platform Crypto / software key stores.
    SYSTEMLOCKERNIGHTFLYER_API std::unique_ptr<IInstallationKeyProvider> makeWindowsCngInstallationKeyProvider();
    /// macOS: P-256 keys and state held in the user's keychain (compiled on Apple targets only).
    SYSTEMLOCKERNIGHTFLYER_API std::unique_ptr<IInstallationKeyProvider> makeMacosKeychainInstallationKeyProvider();

    struct Lease
    {
        std::string compact;
        std::string authorizationId;
        std::uint64_t generation = 0;
        std::int64_t issuedAt = 0;
        std::int64_t expiresAt = 0;
        std::int64_t renewAfter = 0;
        std::string deviceThumbprint;
        std::string deviceId;
        std::string hwidHash;
        std::string signingKeyId;
    };

    struct Status
    {
        std::string compact;
        std::string authorizationId;
        std::uint64_t sequence = 0;
        std::uint64_t keysetSequence = 0;
        std::uint64_t minimumGeneration = 0;
        std::string deviceStatus;
        std::string grantStatus;
        std::vector<std::string> revokedSigningKeyIds;
        std::int64_t issuedAt = 0;
        std::optional<std::int64_t> nextUpdate;
        std::string deviceId;
    };

    struct Decision
    {
        std::string compact;
        std::string responseCode;
        std::string leaseDisposition;
        std::int64_t issuedAt = 0;
        std::optional<std::string> deviceId;
        std::optional<std::string> deviceThumbprint;
        std::optional<bool> occupancyReleased;
        std::optional<std::uint64_t> minimumProtocolVersion;
        std::optional<std::uint64_t> latestProtocolVersion;
        std::optional<std::string> minimumSdkVersion;
        std::optional<std::string> updateUrl;
    };

    struct Problem { std::string type; std::string title; long status = 0; std::string detail; std::string code; };

    struct Response
    {
        long httpStatus = 0;
        std::optional<Lease> lease;
        std::optional<Status> status;
        std::optional<Decision> decision;
        std::optional<Problem> problem;
        std::vector<std::string> keyTransitions;
        std::uint64_t keysetSequence = 0;
        std::optional<std::chrono::seconds> retryAfter;
        bool success() const noexcept { return httpStatus >= 200 && httpStatus < 300; }
    };

    struct PreparedRequest
    {
        std::string endpoint;
        std::string url;
        std::string body;
        std::string proof;
        std::string requestJti;
        std::optional<std::string> presentedLease;
        std::optional<std::string> expectedHwid;
        std::uint64_t keysetSequence = 0;
        std::uint64_t statusSequence = 0;
    };

    class SYSTEMLOCKERNIGHTFLYER_API Client
    {
    public:
        Client(Config config, InstallationKey key, std::shared_ptr<IHttpClient> http);
        ~Client();
        Client(Client&&) noexcept;
        Client& operator=(Client&&) noexcept;
        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;
        Response authorizeWithKey(std::string licenseKey, std::string version, std::string digest, std::string slHwid, int requestedOfflineSeconds, bool persistent, std::uint64_t keysetSequence = 0, std::uint64_t statusSequence = 0);
        Response authorizeWithAccount(std::string username, std::string password, std::string version, std::string digest, std::string slHwid, int requestedOfflineSeconds, bool persistent, std::uint64_t keysetSequence = 0, std::uint64_t statusSequence = 0);
        Response renew(std::string lease, std::string version, std::string digest, std::string slHwid, std::uint64_t keysetSequence = 0, std::uint64_t statusSequence = 0);
        Response status(std::string lease, std::uint64_t keysetSequence = 0, std::uint64_t statusSequence = 0);
        Response end(std::string lease, std::string reason, std::uint64_t keysetSequence = 0, std::uint64_t statusSequence = 0);
        PreparedRequest prepareEnd(std::string lease, std::string reason, std::uint64_t keysetSequence = 0, std::uint64_t statusSequence = 0);
        Response sendPrepared(const PreparedRequest& request);
        Lease verifyCachedLease(const std::string& compact) const;
        Status verifyCachedStatus(const std::string& compact, const std::optional<Lease>& lease) const;
        std::map<std::string, std::string> trustedSigningKeys() const;
    private:
        void restoreTrustedSigningKeyTransitions(const std::vector<std::string>& transitions, std::uint64_t expectedSequence);
        std::string signPersistentState(std::string_view input) const;
        bool verifyPersistentState(std::string_view input, const std::string& signature) const;
        struct Impl;
        std::unique_ptr<Impl> impl_;
        friend class AuthorizationSession;
    };

    enum class AuthorizationState { authorized_online, authorized_offline, renewal_due, expired, ending, ended, inactive, auth_mode_in_use, protocol_upgrade_required, clock_untrusted, device_changed, auth_denied, storage_unavailable, network_unavailable, protocol_failure, installation_in_use };
    struct AuthorizationSnapshot { AuthorizationState state = AuthorizationState::auth_denied; std::optional<Lease> lease; std::string diagnostic; };
    enum class EasyAuthorizationAction { none, continue_offline, retry_online, request_license_key, update_client, check_clock, repair_protected_storage, resolve_device_binding, resolve_authentication_mode, wait_for_installation, contact_developer };
    struct EasyAuthorizationResult
    {
        AuthorizationSnapshot snapshot;
        bool canProceed = false;
        bool isOffline = false;
        bool credentialPresent = false;
        bool shouldPromptForKey = false;
        EasyAuthorizationAction recommendedAction = EasyAuthorizationAction::contact_developer;
        std::optional<std::chrono::seconds> retryAfter;
    };
    struct Binding { std::string version; std::string digest; std::string slHwid; };

    class IStateStore
    {
    public:
        virtual ~IStateStore() = default;
        virtual std::optional<std::vector<unsigned char>> load() = 0;
        virtual void save(const std::vector<unsigned char>& value) = 0;
        virtual void erase() = 0;
        virtual std::string lockIdentity() const = 0;
    };
    SYSTEMLOCKERNIGHTFLYER_API std::unique_ptr<IStateStore> makeWindowsDpapiStateStore(std::string path);
    /// macOS: state held as a keychain generic-password item (Apple targets only).
    SYSTEMLOCKERNIGHTFLYER_API std::unique_ptr<IStateStore> makeMacosKeychainStateStore(std::string serviceName, std::string accountName);

    class SYSTEMLOCKERNIGHTFLYER_API AuthorizationSession
    {
    public:
        static AuthorizationSession memory(Config config, std::shared_ptr<IHttpClient> http = {});
        static AuthorizationSession memory(Config config, InstallationKey key, std::shared_ptr<IHttpClient> http = {});
        static AuthorizationSession persistent(Config config, std::unique_ptr<IStateStore> store, std::shared_ptr<IHttpClient> http = {});
        static AuthorizationSession persistent(Config config, std::unique_ptr<IStateStore> store, std::unique_ptr<IInstallationKeyProvider> keyProvider, std::shared_ptr<IHttpClient> http = {});
        ~AuthorizationSession();
        AuthorizationSession(AuthorizationSession&&) noexcept;
        AuthorizationSession& operator=(AuthorizationSession&&) noexcept;
        AuthorizationSession(const AuthorizationSession&) = delete;
        AuthorizationSession& operator=(const AuthorizationSession&) = delete;
        AuthorizationSnapshot load();
        EasyAuthorizationResult easyAuthorize(const Binding& binding, int requestedOfflineSeconds, std::optional<std::string> licenseKey = {});
        AuthorizationSnapshot authorizeWithKey(std::string licenseKey, const Binding& binding, int requestedOfflineSeconds);
        AuthorizationSnapshot authorizeWithStoredKey(const Binding& binding, int requestedOfflineSeconds);
        AuthorizationSnapshot authorizeWithAccount(std::string username, std::string password, const Binding& binding, int requestedOfflineSeconds);
        AuthorizationSnapshot renewIfDue(const Binding& binding);
        AuthorizationSnapshot tick(const Binding& binding);
        AuthorizationSnapshot synchronizeStatus();
        AuthorizationSnapshot end(std::string reason);
        void forget();
    private:
        struct Impl;
        explicit AuthorizationSession(std::unique_ptr<Impl> impl);
        std::unique_ptr<Impl> impl_;
    };
}
