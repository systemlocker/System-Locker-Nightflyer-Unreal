// Copyright (c) 2026 System Locker. All rights reserved.

#include "internal.hpp"

#include <algorithm>
#include <filesystem>
#include <mutex>
#include <random>
#include <set>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace syslocker::nightflyer
{
    using detail::json;

    namespace
    {
        class ProcessFileLock final
        {
        public:
            explicit ProcessFileLock(std::string identity)
            {
                auto token = detail::sha256(identity);
                std::replace(token.begin(), token.end(), '-', 'a'); std::replace(token.begin(), token.end(), '_', 'b');
                path_ = std::filesystem::temp_directory_path() / ("systemlocker-nightflyer-" + token + ".lock");
#ifdef _WIN32
                handle_ = CreateFileW(path_.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
                if (handle_ == INVALID_HANDLE_VALUE) throw Error(Failure::local_failure, "Could not open the installation lock.");
#else
                descriptor_ = ::open(path_.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
                if (descriptor_ < 0) throw Error(Failure::local_failure, "Could not open the installation lock.");
#endif
            }

            ~ProcessFileLock()
            {
                release();
#ifdef _WIN32
                if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
#else
                if (descriptor_ >= 0) ::close(descriptor_);
#endif
            }

            bool acquire(std::chrono::milliseconds timeout)
            {
                if (held_) return true;
                const auto deadline = std::chrono::steady_clock::now() + timeout;
                do
                {
#ifdef _WIN32
                    OVERLAPPED operation{};
                    if (LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &operation)) { held_ = true; return true; }
#else
                    if (flock(descriptor_, LOCK_EX | LOCK_NB) == 0) { held_ = true; return true; }
#endif
                    if (timeout == std::chrono::milliseconds::zero()) return false;
                    std::this_thread::sleep_for(std::chrono::milliseconds(25));
                } while (std::chrono::steady_clock::now() < deadline);
                return false;
            }

            void release() noexcept
            {
                if (!held_) return;
#ifdef _WIN32
                OVERLAPPED operation{}; (void)UnlockFileEx(handle_, 0, 1, 0, &operation);
#else
                (void)flock(descriptor_, LOCK_UN);
#endif
                held_ = false;
            }
        private:
            std::filesystem::path path_;
            bool held_ = false;
#ifdef _WIN32
            HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
            int descriptor_ = -1;
#endif
        };

        class Gate final
        {
        public:
            Gate(std::timed_mutex& gate, ProcessFileLock* process, std::chrono::milliseconds timeout)
                : gate_(gate), process_(process)
            {
                locked_ = gate_.try_lock_for(timeout);
                if (locked_ && process_ && !process_->acquire(timeout)) { gate_.unlock(); locked_ = false; }
            }
            ~Gate() { if (locked_) { if (process_) process_->release(); gate_.unlock(); } }
            bool locked() const noexcept { return locked_; }
        private:
            std::timed_mutex& gate_;
            ProcessFileLock* process_;
            bool locked_ = false;
        };

        json preparedJson(const PreparedRequest& value)
        {
            json result{{"endpoint", value.endpoint}, {"url", value.url}, {"body", value.body}, {"proof", value.proof}, {"request_jti", value.requestJti}, {"keyset_sequence", value.keysetSequence}, {"status_sequence", value.statusSequence}};
            result["presented_lease"] = value.presentedLease ? json(*value.presentedLease) : json(nullptr);
            result["expected_hwid"] = value.expectedHwid ? json(*value.expectedHwid) : json(nullptr);
            return result;
        }

        PreparedRequest parsePrepared(const json& value)
        {
            detail::exact(value, {"endpoint", "url", "body", "proof", "request_jti", "presented_lease", "expected_hwid", "keyset_sequence", "status_sequence"}, "pending end", Failure::invalid_state);
            PreparedRequest result; result.endpoint = detail::text(value, "endpoint", Failure::invalid_state); result.url = detail::text(value, "url", Failure::invalid_state);
            result.body = detail::text(value, "body", Failure::invalid_state); result.proof = detail::text(value, "proof", Failure::invalid_state); result.requestJti = detail::text(value, "request_jti", Failure::invalid_state);
            if (!value.at("presented_lease").is_null()) result.presentedLease = detail::text(value, "presented_lease", Failure::invalid_state);
            if (!value.at("expected_hwid").is_null()) result.expectedHwid = detail::text(value, "expected_hwid", Failure::invalid_state);
            result.keysetSequence = detail::safeNonnegative(value, "keyset_sequence"); result.statusSequence = detail::safeNonnegative(value, "status_sequence");
            if (result.endpoint != "end" || !result.presentedLease || result.url.empty() || result.body.empty() || result.proof.empty()) throw Error(Failure::invalid_state, "Pending end retry material is invalid.");
            return result;
        }

        bool contains(const std::vector<std::string>& values, const std::string& value)
        {
            return std::find(values.begin(), values.end(), value) != values.end();
        }
    }

    struct AuthorizationSession::Impl
    {
        struct State
        {
            int version = 4;
            std::string systemId;
            std::string installationThumbprint;
            std::string keyReference;
            std::string authorizationId;
            std::optional<std::string> storedLicenseKey;
            std::vector<std::string> keyTransitions;
            std::optional<std::string> stateSignature;
            std::optional<std::string> leaseCompact;
            std::optional<std::string> statusCompact;
            std::uint64_t statusSequence = 0;
            std::uint64_t keysetSequence = 0;
            std::uint64_t highestGeneration = 0;
            std::uint64_t minimumGeneration = 0;
            std::int64_t lastKnownGood = 0;
            std::int64_t serverAnchor = 0;
            std::int64_t anchorMonotonic = 0;
            std::int64_t wallAtAnchor = 0;
            std::string bootIdentifier;
            int retryFailures = 0;
            std::int64_t nextRetry = 0;
            bool ending = false;
            bool ended = false;
            bool revoked = false;
            bool serverExpired = false;
            bool clockUntrusted = false;
            std::optional<PreparedRequest> pendingEnd;
            std::optional<Lease> lease;
            std::optional<Status> status;
            bool allowsUnsignedInitialization = false;
        };

        Config config;
        std::unique_ptr<IStateStore> store;
        std::unique_ptr<IInstallationKeyProvider> keyProvider;
        std::shared_ptr<IHttpClient> http;
        Client client;
        State state;
        bool persistent = false;
        bool forgotten = false;
        std::timed_mutex gate;
        ProcessFileLock processLock;
        bool lifetimeLock = false;

        Impl(Config value, InstallationKey key, std::unique_ptr<IStateStore> stateStore, std::unique_ptr<IInstallationKeyProvider> provider, State initial, std::shared_ptr<IHttpClient> transport)
            : config(std::move(value)), store(std::move(stateStore)), keyProvider(std::move(provider)), http(std::move(transport)),
              client(config, std::move(key), http), state(std::move(initial)), persistent(store != nullptr),
              processLock("Installation:" + config.systemId + ":" + state.installationThumbprint)
        {
            if (persistent && !state.allowsUnsignedInitialization)
            {
                const auto unsignedState = serializeState(state, false).dump(-1, ' ', false, json::error_handler_t::strict);
                if (!state.stateSignature || !client.verifyPersistentState(unsignedState, *state.stateSignature))
                    throw Error(Failure::invalid_state, "Persistent Nightflyer state signature is invalid.");
            }
            verifyRuntime(state);
            if (!persistent)
            {
                if (!processLock.acquire(config.installationLockTimeout)) throw Error(Failure::invalid_state, "Another memory-only Nightflyer session owns this installation.");
                lifetimeLock = true;
            }
        }

        ~Impl()
        {
            if (lifetimeLock) processLock.release();
        }

        static State fresh(const Config& config, const InstallationKey& key, std::string reference)
        {
            State result; result.systemId = config.systemId; result.installationThumbprint = key.thumbprint(); result.keyReference = std::move(reference);
            result.lastKnownGood = config.clock->unixSeconds(); result.wallAtAnchor = result.lastKnownGood;
            result.anchorMonotonic = config.clock->monotonicMilliseconds(); result.bootIdentifier = config.clock->bootIdentifier(); result.allowsUnsignedInitialization = true; return result;
        }

        static void validateLoaded(const Config& config, const State& value)
        {
            if (value.version != 4 || value.systemId != config.systemId || value.installationThumbprint.empty() || value.keyTransitions.size() > 1024
                || (!value.allowsUnsignedInitialization && (!value.stateSignature || value.stateSignature->empty()))
                || value.statusSequence > detail::maximumSafeInteger || value.keysetSequence > detail::maximumSafeInteger
                || value.highestGeneration > detail::maximumSafeInteger || value.minimumGeneration > detail::maximumSafeInteger
                || value.lastKnownGood < 0 || value.lastKnownGood > detail::maximumUnixTimestamp || value.serverAnchor < 0 || value.serverAnchor > detail::maximumUnixTimestamp
                || value.wallAtAnchor < 0 || value.wallAtAnchor > detail::maximumUnixTimestamp || value.anchorMonotonic < 0
                || value.retryFailures < 0 || value.retryFailures > 30 || value.nextRetry < 0 || value.nextRetry > detail::maximumUnixTimestamp
                || value.authorizationId.size() > 256 || (value.storedLicenseKey && value.storedLicenseKey->size() > 4096)
                || (value.ended && value.revoked)) throw Error(Failure::invalid_state, "Persistent Nightflyer state is corrupt or belongs to another system.");
            detail::unb64(value.installationThumbprint, 32, Failure::invalid_state);
            if (value.stateSignature) detail::unb64(*value.stateSignature, 64, Failure::invalid_state);
            for (const auto& transition : value.keyTransitions)
                if (transition.empty() || transition.size() > 65536) throw Error(Failure::invalid_state, "Persistent signing-key transition history is corrupt.");
        }

        static State parseState(const std::vector<unsigned char>& bytes, const Config& config)
        {
            if (bytes.empty() || bytes.size() > 1048576) throw Error(Failure::invalid_state, "Persistent Nightflyer state has an invalid size.");
            const auto value = detail::strictJson(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()), Failure::invalid_state, "Persistent Nightflyer state is corrupt.");
            const auto version = detail::integer(value, "version", Failure::invalid_state);
            const std::vector<std::string> commonFields{"version", "system_id", "installation_thumbprint", "key_reference", "authorization_id", "stored_license_key", "lease", "status", "status_sequence", "keyset_sequence", "highest_generation", "minimum_generation", "last_known_good", "server_anchor", "anchor_monotonic", "wall_at_anchor", "boot_identifier", "retry_failures", "next_retry", "ending", "ended", "revoked", "server_expired", "clock_untrusted", "pending_end"};
            auto expectedFields = commonFields;
            if (version == 3) expectedFields.emplace_back("keys");
            else if (version == 4) { expectedFields.emplace_back("key_transitions"); expectedFields.emplace_back("state_signature"); }
            else throw Error(Failure::invalid_state, "Persistent Nightflyer state version is not supported.");
            detail::exact(value, expectedFields, "persistent state", Failure::invalid_state);

            State result; result.version = static_cast<int>(version); result.systemId = detail::text(value, "system_id", Failure::invalid_state);
            result.installationThumbprint = detail::text(value, "installation_thumbprint", Failure::invalid_state); result.keyReference = detail::text(value, "key_reference", Failure::invalid_state);
            result.authorizationId = detail::text(value, "authorization_id", Failure::invalid_state);
            if (!value.at("stored_license_key").is_null()) result.storedLicenseKey = detail::text(value, "stored_license_key", Failure::invalid_state);
            std::map<std::string, std::string> legacyKeys;
            try
            {
                if (version == 3) legacyKeys = value.at("keys").get<std::map<std::string, std::string>>();
                else
                {
                    result.keyTransitions = value.at("key_transitions").get<std::vector<std::string>>();
                    result.stateSignature = detail::text(value, "state_signature", Failure::invalid_state);
                }
            }
            catch (const json::exception&) { throw Error(Failure::invalid_state, "Persistent signing-key state is corrupt."); }
            if (!value.at("lease").is_null()) result.leaseCompact = detail::text(value, "lease", Failure::invalid_state);
            if (!value.at("status").is_null()) result.statusCompact = detail::text(value, "status", Failure::invalid_state);
            result.statusSequence = detail::safeNonnegative(value, "status_sequence"); result.keysetSequence = detail::safeNonnegative(value, "keyset_sequence");
            result.highestGeneration = detail::safeNonnegative(value, "highest_generation"); result.minimumGeneration = detail::safeNonnegative(value, "minimum_generation");
            result.lastKnownGood = detail::integer(value, "last_known_good", Failure::invalid_state); result.serverAnchor = detail::integer(value, "server_anchor", Failure::invalid_state);
            result.anchorMonotonic = detail::integer(value, "anchor_monotonic", Failure::invalid_state); result.wallAtAnchor = detail::integer(value, "wall_at_anchor", Failure::invalid_state);
            result.bootIdentifier = detail::text(value, "boot_identifier", Failure::invalid_state); result.retryFailures = static_cast<int>(detail::integer(value, "retry_failures", Failure::invalid_state)); result.nextRetry = detail::integer(value, "next_retry", Failure::invalid_state);
            for (const auto* field : {"ending", "ended", "revoked", "server_expired", "clock_untrusted"}) if (!value.at(field).is_boolean()) throw Error(Failure::invalid_state, "Persistent terminal state is corrupt.");
            result.ending = value.at("ending").get<bool>(); result.ended = value.at("ended").get<bool>(); result.revoked = value.at("revoked").get<bool>(); result.serverExpired = value.at("server_expired").get<bool>(); result.clockUntrusted = value.at("clock_untrusted").get<bool>();
            if (!value.at("pending_end").is_null()) result.pendingEnd = parsePrepared(value.at("pending_end"));

            if (version == 3)
            {
                for (const auto& [kid, key] : config.trustedSigningKeys)
                {
                    const auto found = legacyKeys.find(kid);
                    if (found == legacyKeys.end() || !detail::fixedEqual(found->second, key)) throw Error(Failure::invalid_state, "Legacy state no longer contains the application's pinned trust root.");
                }

                // Version 3 stored a derived key ring without proof of how its
                // keys were authorized. Preserve only installation identity and
                // the user's credential; online authorization rebuilds all
                // security-sensitive state under the authenticated v4 format.
                result.version = 4; result.authorizationId.clear(); result.keyTransitions.clear(); result.leaseCompact.reset(); result.statusCompact.reset();
                result.statusSequence = 0; result.keysetSequence = 0; result.highestGeneration = 0; result.minimumGeneration = 0;
                result.lastKnownGood = config.clock->unixSeconds(); result.serverAnchor = 0; result.anchorMonotonic = config.clock->monotonicMilliseconds();
                result.wallAtAnchor = result.lastKnownGood; result.bootIdentifier = config.clock->bootIdentifier(); result.retryFailures = 0; result.nextRetry = 0;
                result.ending = false; result.ended = false; result.revoked = false; result.serverExpired = false; result.clockUntrusted = false; result.pendingEnd.reset();
                result.stateSignature.reset(); result.allowsUnsignedInitialization = true;
            }
            validateLoaded(config, result); return result;
        }

        static json serializeState(const State& state, bool includeSignature)
        {
            json value{{"version", state.version}, {"system_id", state.systemId}, {"installation_thumbprint", state.installationThumbprint}, {"key_reference", state.keyReference}, {"authorization_id", state.authorizationId}, {"key_transitions", state.keyTransitions},
                {"status_sequence", state.statusSequence}, {"keyset_sequence", state.keysetSequence}, {"highest_generation", state.highestGeneration}, {"minimum_generation", state.minimumGeneration},
                {"last_known_good", state.lastKnownGood}, {"server_anchor", state.serverAnchor}, {"anchor_monotonic", state.anchorMonotonic}, {"wall_at_anchor", state.wallAtAnchor}, {"boot_identifier", state.bootIdentifier},
                {"retry_failures", state.retryFailures}, {"next_retry", state.nextRetry}, {"ending", state.ending}, {"ended", state.ended}, {"revoked", state.revoked}, {"server_expired", state.serverExpired}, {"clock_untrusted", state.clockUntrusted}};
            value["stored_license_key"] = state.storedLicenseKey ? json(*state.storedLicenseKey) : json(nullptr);
            value["lease"] = state.leaseCompact ? json(*state.leaseCompact) : json(nullptr); value["status"] = state.statusCompact ? json(*state.statusCompact) : json(nullptr);
            value["pending_end"] = state.pendingEnd ? preparedJson(*state.pendingEnd) : json(nullptr);
            if (includeSignature) value["state_signature"] = state.stateSignature ? json(*state.stateSignature) : json(nullptr);
            return value;
        }

        void verifyRuntime(State& value)
        {
            client.restoreTrustedSigningKeyTransitions(value.keyTransitions, value.keysetSequence);
            value.lease = value.leaseCompact ? std::optional<Lease>(client.verifyCachedLease(*value.leaseCompact)) : std::nullopt;
            value.status = value.statusCompact ? std::optional<Status>(client.verifyCachedStatus(*value.statusCompact, value.lease)) : std::nullopt;
            if (value.lease && (value.lease->generation != value.highestGeneration || value.lease->generation < value.minimumGeneration)) throw Error(Failure::invalid_state, "Persistent lease conflicts with generation high-water marks.");
            if (value.lease && !detail::fixedEqual(value.lease->authorizationId, value.authorizationId)) throw Error(Failure::invalid_state, "Persistent lease belongs to another authorization epoch.");
            if (value.status && (value.status->sequence != value.statusSequence || value.status->keysetSequence > value.keysetSequence || value.status->minimumGeneration != value.minimumGeneration)) throw Error(Failure::invalid_state, "Persistent status conflicts with sequence high-water marks.");
            if (value.lease && value.status && (value.lease->authorizationId != value.status->authorizationId || value.lease->deviceId != value.status->deviceId)) throw Error(Failure::invalid_state, "Persistent status belongs to another lease.");
            if (value.ending && (!value.pendingEnd || !value.lease)) throw Error(Failure::invalid_state, "Persistent end tombstone lacks exact retry material.");
        }

        void reload()
        {
            if (!persistent) return;
            auto bytes = store->load(); if (!bytes) throw Error(Failure::invalid_state, "Shared Nightflyer state disappeared.");
            auto loaded = parseState(*bytes, config);
            if (!detail::fixedEqual(loaded.installationThumbprint, state.installationThumbprint) || !detail::fixedEqual(loaded.keyReference, state.keyReference)) throw Error(Failure::invalid_state, "Shared state belongs to another installation key.");
            if (!loaded.allowsUnsignedInitialization)
            {
                const auto unsignedState = serializeState(loaded, false).dump(-1, ' ', false, json::error_handler_t::strict);
                if (!loaded.stateSignature || !client.verifyPersistentState(unsignedState, *loaded.stateSignature)) throw Error(Failure::invalid_state, "Persistent Nightflyer state signature is invalid.");
            }
            const auto previousTransitions = state.keyTransitions; const auto previousSequence = state.keysetSequence;
            try { verifyRuntime(loaded); state = std::move(loaded); }
            catch (...) { client.restoreTrustedSigningKeyTransitions(previousTransitions, previousSequence); throw; }
        }

        std::optional<std::int64_t> anchoredTime() const
        {
            if (state.serverAnchor <= 0 || state.bootIdentifier != config.clock->bootIdentifier()) return {};
            const auto monotonic = config.clock->monotonicMilliseconds();
            if (monotonic < state.anchorMonotonic) return {};
            const auto elapsed = (monotonic - state.anchorMonotonic) / 1000;
            // Saturate so even an extreme custom counter expires the lease
            // without overflowing the supported timestamp range.
            return state.serverAnchor + std::min(elapsed, detail::maximumUnixTimestamp - state.serverAnchor);
        }

        std::int64_t effectiveNow() const
        {
            // Wall-clock corrections do not shorten or extend a signed lease
            // while the same suspend-inclusive boot counter is available.
            const auto anchored = anchoredTime();
            return std::max(state.lastKnownGood, anchored ? *anchored : config.clock->unixSeconds());
        }

        bool clockIsUntrusted() const
        {
            if (state.clockUntrusted) return true;
            if (const auto anchored = anchoredTime()) return *anchored + 5 < state.lastKnownGood;
            // A same-boot counter reset is not a harmless UTC correction.
            if (state.serverAnchor > 0 && state.bootIdentifier == config.clock->bootIdentifier()) return true;
            return (persistent && config.clock->unixSeconds() + 5 < state.lastKnownGood)
                || (persistent && config.requireOnlineAfterReboot && state.serverAnchor > 0 && state.bootIdentifier != config.clock->bootIdentifier());
        }

        std::optional<Lease> usableLease() const
        {
            if (state.ending || state.ended || state.revoked || !state.lease || clockIsUntrusted() || state.serverExpired || effectiveNow() >= state.lease->expiresAt) return {};
            return state.lease;
        }

        AuthorizationSnapshot snapshot(std::string diagnostic = {}, bool online = false) const
        {
            if (state.ending) return {AuthorizationState::ending, {}, std::move(diagnostic)};
            if (state.revoked) return {AuthorizationState::inactive, {}, std::move(diagnostic)};
            if (state.ended) return {AuthorizationState::ended, {}, std::move(diagnostic)};
            if (!state.lease) return {AuthorizationState::auth_denied, {}, std::move(diagnostic)};
            if (clockIsUntrusted()) return {AuthorizationState::clock_untrusted, {}, diagnostic.empty() ? "The protected time checkpoint is not trusted until an online check succeeds." : std::move(diagnostic)};
            if (state.serverExpired || effectiveNow() >= state.lease->expiresAt) return {AuthorizationState::expired, {}, std::move(diagnostic)};
            if (effectiveNow() >= state.lease->renewAfter) return {AuthorizationState::renewal_due, state.lease, std::move(diagnostic)};
            return {online ? AuthorizationState::authorized_online : AuthorizationState::authorized_offline, state.lease, std::move(diagnostic)};
        }

        void persist()
        {
            if (!persistent) return;
            state.lastKnownGood = std::max(state.lastKnownGood, effectiveNow());
            const auto unsignedState = serializeState(state, false).dump(-1, ' ', false, json::error_handler_t::strict);
            state.stateSignature = client.signPersistentState(unsignedState);
            state.allowsUnsignedInitialization = false;
            const auto text = serializeState(state, true).dump(-1, ' ', false, json::error_handler_t::strict);
            store->save(std::vector<unsigned char>(text.begin(), text.end()));
        }

        void applyStatus(const Status& status)
        {
            if (!state.lease) return;
            if (status.deviceStatus == "revoked" || status.grantStatus == "revoked" || status.minimumGeneration > state.lease->generation || contains(status.revokedSigningKeyIds, state.lease->signingKeyId))
            {
                state.revoked = true; state.ended = false; state.lease.reset(); state.leaseCompact.reset(); state.pendingEnd.reset(); state.ending = false;
            }
            else if (status.grantStatus == "ended")
            {
                state.ended = true; state.revoked = false; state.lease.reset(); state.leaseCompact.reset(); state.pendingEnd.reset(); state.ending = false;
            }
            else if (status.grantStatus == "reclaim_pending") state.serverExpired = true;
        }

        void applyDecision(const Decision& decision)
        {
            if (decision.leaseDisposition == "revoked") { state.revoked = true; state.ended = false; state.lease.reset(); state.leaseCompact.reset(); state.pendingEnd.reset(); state.ending = false; }
            else if (decision.leaseDisposition == "ended") { state.ended = true; state.revoked = false; state.lease.reset(); state.leaseCompact.reset(); state.pendingEnd.reset(); state.ending = false; }
            else if (decision.leaseDisposition == "expired") state.serverExpired = true;
        }

        void accept(const Response& response, bool freshAuthorization = false)
        {
            if (response.keysetSequence < state.keysetSequence || (response.status && response.status->sequence < state.statusSequence)) throw Error(Failure::invalid_state, "Server sequence moved backwards; local state may have been rolled back.");
            if (!freshAuthorization && response.lease && response.lease->generation < state.highestGeneration) throw Error(Failure::invalid_state, "Lease generation moved backwards.");
            if (response.decision && response.decision->responseCode == "STALE_GENERATION") { reload(); return; }
            auto acceptedTransitions = state.keyTransitions;
            acceptedTransitions.insert(acceptedTransitions.end(), response.keyTransitions.begin(), response.keyTransitions.end());
            try
            {
                // Rebuild from the application's immutable trust roots. This
                // proves the persisted derivation path instead of trusting the
                // mutable key ring that happened to verify this response.
                client.restoreTrustedSigningKeyTransitions(acceptedTransitions, response.keysetSequence);
            }
            catch (...)
            {
                client.restoreTrustedSigningKeyTransitions(state.keyTransitions, state.keysetSequence);
                throw;
            }
            state.keyTransitions = std::move(acceptedTransitions); state.keysetSequence = response.keysetSequence;
            if (response.lease)
            {
                if (freshAuthorization)
                {
                    // A signed /authorize lease starts a new lease epoch, so
                    // terminal state and high-water marks from the old grant
                    // cannot poison a legitimate reactivation.
                    state.ending = false; state.ended = false; state.revoked = false; state.serverExpired = false; state.pendingEnd.reset();
                    state.status.reset(); state.statusCompact.reset(); state.minimumGeneration = 0;
                    state.highestGeneration = response.lease->generation; state.authorizationId = response.lease->authorizationId;
                }
                state.lease = response.lease; state.leaseCompact = response.lease->compact; state.highestGeneration = std::max(state.highestGeneration, response.lease->generation); state.serverExpired = false;
            }
            if (response.status) { state.status = response.status; state.statusCompact = response.status->compact; state.statusSequence = response.status->sequence; state.minimumGeneration = response.status->minimumGeneration; applyStatus(*response.status); }
            if (response.decision) applyDecision(*response.decision);
            std::optional<std::int64_t> serverTime;
            if (response.status) serverTime = response.status->issuedAt; else if (response.decision) serverTime = response.decision->issuedAt; else if (response.lease) serverTime = response.lease->issuedAt;
            if (serverTime)
            {
                // Verified, request-bound time repairs a bad local checkpoint;
                // an incorrect future wall clock must not permanently win.
                const auto wall = config.clock->unixSeconds(); state.clockUntrusted = false; state.serverAnchor = *serverTime;
                state.anchorMonotonic = config.clock->monotonicMilliseconds(); state.bootIdentifier = config.clock->bootIdentifier(); state.wallAtAnchor = wall; state.lastKnownGood = *serverTime;
            }
            state.retryFailures = 0; state.nextRetry = 0; persist();
        }

        AuthorizationSnapshot responseSnapshot(const Response& response, bool freshAuthorization = false)
        {
            if (!response.decision) return snapshot({}, true);
            const auto& code = response.decision->responseCode;
            if (code == "LEASE_REVOKED") return {AuthorizationState::inactive, {}, code};
            if (code == "LEASE_ENDED") return {AuthorizationState::ended, {}, code};
            if (code == "PROTOCOL_UPGRADE_REQUIRED") return {AuthorizationState::protocol_upgrade_required, usableLease(), code};
            if (code == "AUTH_MODE_IN_USE" || code == "LEASE_ALREADY_ACTIVE") return {AuthorizationState::auth_mode_in_use, usableLease(), code};
            if (code == "DEVICE_BINDING_MISMATCH") return {AuthorizationState::device_changed, {}, code};
            if (code == "STALE_GENERATION") return snapshot(code);
            if (code == "LEASE_RECLAIM_PENDING" || response.decision->leaseDisposition == "expired") return {AuthorizationState::expired, {}, code};
            if (response.success()) return snapshot(code, true);
            if (freshAuthorization) return {AuthorizationState::auth_denied, usableLease(), code};
            if (state.revoked) return {AuthorizationState::inactive, {}, code};
            if (state.ended) return {AuthorizationState::ended, {}, code};
            return {AuthorizationState::auth_denied, usableLease(), code};
        }

        void scheduleRetry(std::optional<std::chrono::seconds> retryAfter)
        {
            state.retryFailures = std::min(state.retryFailures + 1, 30); const auto now = config.clock->unixSeconds();
            const auto leaseCeiling = state.lease ? std::max<std::int64_t>(0, std::min<std::int64_t>(600, (state.lease->expiresAt - now) / 3)) : 600;
            const auto exponential = std::min<std::int64_t>(leaseCeiling, 30LL * (1LL << std::min(state.retryFailures - 1, 4)));
            std::int64_t delay = 0;
            if (retryAfter) delay = std::max<std::int64_t>(0, retryAfter->count());
            else { std::random_device random; std::uniform_int_distribution<std::int64_t> distribution(0, std::max<std::int64_t>(0, exponential)); delay = distribution(random); }
            if (state.lease) delay = std::min(delay, std::max<std::int64_t>(0, state.lease->expiresAt - now));
            state.nextRetry = now + delay; persist();
        }

        AuthorizationSnapshot execute(const std::function<Response()>& operation, bool freshAuthorization = false, bool forgetMissingKey = false)
        {
            try
            {
                auto response = operation();
                const auto responseCode = response.decision ? response.decision->responseCode : (response.problem ? response.problem->code : std::string{});
                const auto signedMissingKey = forgetMissingKey && response.decision && response.decision->responseCode == "KEY_NOT_FOUND";
                if (response.lease || response.decision || response.status) accept(response, freshAuthorization);
                // Never erase a credential because an unsigned Problem Details
                // body claimed it was missing.
                if (signedMissingKey) { state.storedLicenseKey.reset(); persist(); }
                if (response.httpStatus == 429 || response.httpStatus >= 500)
                {
                    scheduleRetry(response.retryAfter); return {AuthorizationState::network_unavailable, usableLease(), response.problem ? response.problem->code : (response.decision ? response.decision->responseCode : "SERVICE_UNAVAILABLE")};
                }
                if (signedMissingKey) return {AuthorizationState::auth_denied, {}, responseCode};
                if (!response.success() && !response.decision) return {AuthorizationState::protocol_failure, {}, response.problem ? response.problem->code : "Unsigned Nightflyer request failure."};
                return responseSnapshot(response, freshAuthorization);
            }
            catch (const Error& error)
            {
                if (error.failure() != Failure::transport) throw;
                scheduleRetry({}); return {AuthorizationState::network_unavailable, usableLease(), "Network request failed; the signed lease is unchanged."};
            }
        }

        void orderlyDispose() noexcept
        {
            if (persistent || forgotten || !state.lease || state.ended || state.revoked) return;
            try
            {
                std::unique_lock<std::timed_mutex> lock(gate, std::defer_lock);
                if (lock.try_lock_for(config.installationLockTimeout)) (void)endLocked("process_shutdown");
            }
            catch (...) {}
        }

        AuthorizationSnapshot endLocked(std::string reason)
        {
            if (state.ended || (!state.lease && !state.pendingEnd)) return snapshot();
            if (!state.pendingEnd)
            {
                state.pendingEnd = client.prepareEnd(state.lease->compact, std::move(reason), state.keysetSequence, state.statusSequence); state.ending = true; persist();
            }
            try
            {
                auto response = client.sendPrepared(*state.pendingEnd);
                if (response.httpStatus == 429 || response.httpStatus >= 500) { scheduleRetry(response.retryAfter); return {AuthorizationState::ending, {}, response.problem ? response.problem->code : "The end request is waiting for an exact retry."}; }
                accept(response);
                if (state.revoked) return snapshot(response.decision ? response.decision->responseCode : "");
                if (!response.decision || (response.decision->responseCode != "LEASE_ENDED" && response.decision->leaseDisposition != "ended")) throw Error(Failure::invalid_state, "Server did not acknowledge terminal end state.");
                state.ending = false; state.ended = true; state.lease.reset(); state.leaseCompact.reset(); state.pendingEnd.reset(); persist();
                return {AuthorizationState::ended, {}, response.decision->responseCode};
            }
            catch (const Error& error)
            {
                if (error.failure() != Failure::transport) throw;
                scheduleRetry({}); return {AuthorizationState::ending, {}, "The exact end request is retained for retry."};
            }
        }
    };

    AuthorizationSession::AuthorizationSession(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
    AuthorizationSession::~AuthorizationSession() { if (impl_) impl_->orderlyDispose(); }
    AuthorizationSession::AuthorizationSession(AuthorizationSession&&) noexcept = default;
    AuthorizationSession& AuthorizationSession::operator=(AuthorizationSession&& other) noexcept
    {
        if (this != &other) { if (impl_) impl_->orderlyDispose(); impl_ = std::move(other.impl_); }
        return *this;
    }

    AuthorizationSession AuthorizationSession::memory(Config config, std::shared_ptr<IHttpClient> http)
    {
#ifdef _WIN32
        auto provider = makeWindowsCngInstallationKeyProvider(); auto handle = provider->openOrCreateStable(config.systemId); auto state = Impl::fresh(config, handle.key, handle.reference);
        return AuthorizationSession(std::make_unique<Impl>(std::move(config), std::move(handle.key), nullptr, std::move(provider), std::move(state), std::move(http)));
#else
        return memory(std::move(config), InstallationKey::ephemeral(), std::move(http));
#endif
    }

    AuthorizationSession AuthorizationSession::memory(Config config, InstallationKey key, std::shared_ptr<IHttpClient> http)
    {
        auto state = Impl::fresh(config, key, {}); return AuthorizationSession(std::make_unique<Impl>(std::move(config), std::move(key), nullptr, nullptr, std::move(state), std::move(http)));
    }

    AuthorizationSession AuthorizationSession::persistent(Config config, std::unique_ptr<IStateStore> store, std::shared_ptr<IHttpClient> http)
    {
        return persistent(std::move(config), std::move(store), makeWindowsCngInstallationKeyProvider(), std::move(http));
    }

    AuthorizationSession AuthorizationSession::persistent(Config config, std::unique_ptr<IStateStore> store, std::unique_ptr<IInstallationKeyProvider> provider, std::shared_ptr<IHttpClient> http)
    {
        if (!store || !provider) throw Error(Failure::configuration, "Persistent Nightflyer mode requires protected state and installation-key providers.");
        ProcessFileLock bootstrap("Bootstrap:" + config.systemId + ":" + store->lockIdentity());
        if (!bootstrap.acquire(config.installationLockTimeout)) throw Error(Failure::invalid_state, "Another process is opening this Nightflyer state.");
        struct Release { ProcessFileLock& lock; ~Release() { lock.release(); } } release{bootstrap};
        auto bytes = store->load();
        Impl::State state = bytes ? Impl::parseState(*bytes, config) : Impl::State{};
        InstallationKeyHandle handle = bytes ? provider->load(config.systemId, state.keyReference) : provider->create(config.systemId);
        if (!bytes) state = Impl::fresh(config, handle.key, handle.reference);
        if (!detail::fixedEqual(handle.key.thumbprint(), state.installationThumbprint)) throw Error(Failure::invalid_state, "Persistent state belongs to another installation key.");
        auto result = AuthorizationSession(std::make_unique<Impl>(config, std::move(handle.key), std::move(store), std::move(provider), std::move(state), std::move(http)));
        result.impl_->persist(); return result;
    }

    AuthorizationSnapshot AuthorizationSession::load()
    {
        if (!impl_ || impl_->forgotten) throw Error(Failure::invalid_state, "This Nightflyer installation is unavailable.");
        Gate lock(impl_->gate, impl_->persistent ? &impl_->processLock : nullptr, impl_->config.installationLockTimeout); if (!lock.locked()) return {AuthorizationState::installation_in_use, {}, "Another process is updating this installation."};
        impl_->reload(); return impl_->snapshot();
    }

    EasyAuthorizationResult AuthorizationSession::easyAuthorize(const Binding& binding, int seconds, std::optional<std::string> licenseKey)
    {
        AuthorizationSnapshot result;
        try
        {
            if (licenseKey)
            {
                result = authorizeWithKey(std::move(*licenseKey), binding, seconds);
            }
            else
            {
                result = load();
                if (result.state == AuthorizationState::renewal_due) result = renewIfDue(binding);
                else if (result.state == AuthorizationState::authorized_offline || result.state == AuthorizationState::clock_untrusted) result = synchronizeStatus();
                // A prior ambiguous end must finish with its exact persisted
                // request before this installation can start a new lease epoch.
                else if (result.state == AuthorizationState::ending) result = end("resume_pending_end");

                if (result.state == AuthorizationState::inactive || result.state == AuthorizationState::ended
                    || result.state == AuthorizationState::expired || result.state == AuthorizationState::auth_denied)
                    result = authorizeWithStoredKey(binding, seconds);
            }
        }
        catch (const Error& error)
        {
            if (error.failure() == Failure::invalid_state || error.failure() == Failure::local_failure)
                result = {AuthorizationState::storage_unavailable, {}, error.what()};
            else if (error.failure() == Failure::invalid_response || error.failure() == Failure::invalid_signature || error.failure() == Failure::invalid_token)
                result = {AuthorizationState::protocol_failure, {}, error.what()};
            else if (error.failure() == Failure::transport)
                result = {AuthorizationState::network_unavailable, {}, error.what()};
            else throw;
        }

        bool credentialPresent = false;
        std::optional<std::chrono::seconds> retryAfter;
        try
        {
            // Re-read shared state after the network workflow so guidance
            // reflects credential deletion and retry scheduling by peers.
            Gate lock(impl_->gate, impl_->persistent ? &impl_->processLock : nullptr, impl_->config.installationLockTimeout);
            if (lock.locked())
            {
                impl_->reload();
                credentialPresent = impl_->state.storedLicenseKey.has_value();
                const auto remaining = impl_->state.nextRetry - impl_->config.clock->unixSeconds();
                if (remaining > 0) retryAfter = std::chrono::seconds(remaining);
            }
        }
        catch (const Error& error)
        {
            result = {AuthorizationState::storage_unavailable, {}, error.what()};
        }

        EasyAuthorizationAction action = EasyAuthorizationAction::contact_developer;
        switch (result.state)
        {
        case AuthorizationState::authorized_online: action = EasyAuthorizationAction::none; break;
        case AuthorizationState::authorized_offline: action = EasyAuthorizationAction::continue_offline; break;
        case AuthorizationState::renewal_due:
        case AuthorizationState::network_unavailable:
        case AuthorizationState::ending: action = EasyAuthorizationAction::retry_online; break;
        case AuthorizationState::inactive:
        case AuthorizationState::ended:
        case AuthorizationState::expired:
        case AuthorizationState::auth_denied: action = EasyAuthorizationAction::request_license_key; break;
        case AuthorizationState::protocol_upgrade_required: action = EasyAuthorizationAction::update_client; break;
        case AuthorizationState::clock_untrusted: action = EasyAuthorizationAction::check_clock; break;
        case AuthorizationState::storage_unavailable: action = EasyAuthorizationAction::repair_protected_storage; break;
        case AuthorizationState::device_changed: action = EasyAuthorizationAction::resolve_device_binding; break;
        case AuthorizationState::auth_mode_in_use: action = EasyAuthorizationAction::resolve_authentication_mode; break;
        case AuthorizationState::installation_in_use: action = EasyAuthorizationAction::wait_for_installation; break;
        default: break;
        }

        const auto canProceed = result.lease.has_value();
        const auto isOffline = canProceed && result.state != AuthorizationState::authorized_online;
        return {std::move(result), canProceed, isOffline,
            credentialPresent, action == EasyAuthorizationAction::request_license_key, action, retryAfter};
    }

    AuthorizationSnapshot AuthorizationSession::authorizeWithKey(std::string licenseKey, const Binding& binding, int seconds)
    {
        Gate lock(impl_->gate, impl_->persistent ? &impl_->processLock : nullptr, impl_->config.installationLockTimeout); if (!lock.locked()) return {AuthorizationState::installation_in_use, {}, "Another process is updating this installation."};
        impl_->reload();
        if (licenseKey.empty() || licenseKey.size() > 160) throw Error(Failure::configuration, "License key must contain between 1 and 160 characters.");
        impl_->state.storedLicenseKey = licenseKey; impl_->persist();
        return impl_->execute([&] { return impl_->client.authorizeWithKey(std::move(licenseKey), binding.version, binding.digest, binding.slHwid, seconds, impl_->persistent, impl_->state.keysetSequence, impl_->state.statusSequence); }, true, true);
    }

    AuthorizationSnapshot AuthorizationSession::authorizeWithStoredKey(const Binding& binding, int seconds)
    {
        Gate lock(impl_->gate, impl_->persistent ? &impl_->processLock : nullptr, impl_->config.installationLockTimeout); if (!lock.locked()) return {AuthorizationState::installation_in_use, {}, "Another process is updating this installation."};
        impl_->reload(); if (!impl_->state.storedLicenseKey) return {AuthorizationState::auth_denied, {}, "NO_STORED_LICENSE_KEY"};
        auto licenseKey = *impl_->state.storedLicenseKey;
        return impl_->execute([&] { return impl_->client.authorizeWithKey(std::move(licenseKey), binding.version, binding.digest, binding.slHwid, seconds, impl_->persistent, impl_->state.keysetSequence, impl_->state.statusSequence); }, true, true);
    }

    AuthorizationSnapshot AuthorizationSession::authorizeWithAccount(std::string username, std::string password, const Binding& binding, int seconds)
    {
        Gate lock(impl_->gate, impl_->persistent ? &impl_->processLock : nullptr, impl_->config.installationLockTimeout); if (!lock.locked()) return {AuthorizationState::installation_in_use, {}, "Another process is updating this installation."};
        impl_->reload(); return impl_->execute([&] { return impl_->client.authorizeWithAccount(std::move(username), std::move(password), binding.version, binding.digest, binding.slHwid, seconds, impl_->persistent, impl_->state.keysetSequence, impl_->state.statusSequence); }, true);
    }

    AuthorizationSnapshot AuthorizationSession::renewIfDue(const Binding& binding)
    {
        Gate lock(impl_->gate, impl_->persistent ? &impl_->processLock : nullptr, impl_->config.installationLockTimeout); if (!lock.locked()) return {AuthorizationState::installation_in_use, {}, "Another process is updating this installation."};
        impl_->reload(); auto local = impl_->snapshot(); if (!impl_->state.lease || local.state != AuthorizationState::renewal_due || impl_->state.nextRetry > impl_->config.clock->unixSeconds()) return local;
        return impl_->execute([&] { return impl_->client.renew(impl_->state.lease->compact, binding.version, binding.digest, binding.slHwid, impl_->state.keysetSequence, impl_->state.statusSequence); });
    }

    AuthorizationSnapshot AuthorizationSession::tick(const Binding& binding)
    {
        auto result = renewIfDue(binding); if (!impl_->persistent && result.state == AuthorizationState::expired) return end("lease_expired"); return result;
    }

    AuthorizationSnapshot AuthorizationSession::synchronizeStatus()
    {
        Gate lock(impl_->gate, impl_->persistent ? &impl_->processLock : nullptr, impl_->config.installationLockTimeout); if (!lock.locked()) return {AuthorizationState::installation_in_use, {}, "Another process is updating this installation."};
        impl_->reload(); if (!impl_->state.lease) return impl_->snapshot(); return impl_->execute([&] { return impl_->client.status(impl_->state.lease->compact, impl_->state.keysetSequence, impl_->state.statusSequence); });
    }

    AuthorizationSnapshot AuthorizationSession::end(std::string reason)
    {
        Gate lock(impl_->gate, impl_->persistent ? &impl_->processLock : nullptr, impl_->config.installationLockTimeout); if (!lock.locked()) return {AuthorizationState::installation_in_use, {}, "Another process is updating this installation."};
        impl_->reload(); return impl_->endLocked(std::move(reason));
    }

    void AuthorizationSession::forget()
    {
        Gate lock(impl_->gate, impl_->persistent ? &impl_->processLock : nullptr, impl_->config.installationLockTimeout); if (!lock.locked()) throw Error(Failure::invalid_state, "Another process is updating this installation.");
        impl_->reload(); if (impl_->state.lease || impl_->state.ending) throw Error(Failure::invalid_state, "Refusing to forget an active or pending Nightflyer lease; end it first.");
        if (impl_->keyProvider && !impl_->state.keyReference.empty()) impl_->keyProvider->erase(impl_->config.systemId, impl_->state.keyReference);
        impl_->forgotten = true; if (impl_->store) impl_->store->erase();
    }
}
