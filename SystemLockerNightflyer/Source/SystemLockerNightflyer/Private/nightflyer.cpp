#include "internal.hpp"

#include "ed25519/ed25519.h"
#include "micro-ecc/uECC.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <sstream>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__linux__)
#include <time.h>
#elif defined(__APPLE__)
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#endif

namespace syslocker::nightflyer
{
    using detail::json;

    Error::Error(Failure failure, std::string message, std::optional<long> httpStatus, std::optional<std::chrono::seconds> retryAfter)
        : std::runtime_error(std::move(message)), failure_(failure), httpStatus_(httpStatus), retryAfter_(retryAfter) {}

    namespace
    {
        class SystemClock final : public IClock
        {
        public:
            std::int64_t unixSeconds() const override
            {
                return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            }

            std::int64_t monotonicMilliseconds() const override
            {
#ifdef _WIN32
                return static_cast<std::int64_t>(GetTickCount64());
#elif defined(__linux__)
                timespec value{};
                if (clock_gettime(CLOCK_BOOTTIME, &value) != 0) throw Error(Failure::local_failure, "CLOCK_BOOTTIME is unavailable.");
                return value.tv_sec * 1000LL + value.tv_nsec / 1000000LL;
#elif defined(__APPLE__)
                mach_timebase_info_data_t info{};
                if (mach_timebase_info(&info) != KERN_SUCCESS || info.denom == 0) throw Error(Failure::local_failure, "mach_continuous_time is unavailable.");
                return static_cast<std::int64_t>((static_cast<long double>(mach_continuous_time()) * info.numer / info.denom) / 1000000.0L);
#else
                // A counter that pauses during sleep would extend the lease.
                throw Error(Failure::local_failure, "A suspend-inclusive clock adapter is required on this platform.");
#endif
            }

            std::string bootIdentifier() const override
            {
                static const auto identifier = readBootIdentifier();
                return identifier;
            }

        private:
            static std::string readBootIdentifier()
            {
#ifdef _WIN32
                // The optional NT boot GUID is independent of wall-clock edits.
                // Resolve at runtime rather than requiring a private import.
                struct BootEnvironment { GUID identifier; ULONG firmwareType; ULONGLONG flags; };
                using Query = LONG (WINAPI*)(ULONG, void*, ULONG, ULONG*);
                const auto module = GetModuleHandleW(L"ntdll.dll");
                const auto query = module ? reinterpret_cast<Query>(GetProcAddress(module, "NtQuerySystemInformation")) : nullptr;
                BootEnvironment boot{}; ULONG length = 0;
                if (query && query(90, &boot, sizeof(boot), &length) >= 0 && length >= sizeof(GUID))
                {
                    const auto* bytes = reinterpret_cast<const unsigned char*>(&boot.identifier);
                    if (std::any_of(bytes, bytes + sizeof(GUID), [](unsigned char value) { return value != 0; }))
                        return "windows-" + detail::b64(bytes, sizeof(GUID));
                }
#elif defined(__linux__)
                std::ifstream input("/proc/sys/kernel/random/boot_id");
                std::string value;
                if (std::getline(input, value) && !value.empty()) return value;
#elif defined(__APPLE__)
                std::array<char, 37> boot{};
                std::size_t size = boot.size();
                if (sysctlbyname("kern.bootsessionuuid", boot.data(), &size, nullptr, 0) == 0 && size > 1 && size <= boot.size() && boot[size - 1] == '\0')
                    return "macos-" + std::string(boot.data(), size - 1);
#endif
                // No wall-clock estimates: an unavailable OS identifier limits
                // elapsed-time reuse to this process. Reopens use UTC checks.
                std::array<unsigned char, 16> random{};
                try { crypto::random(random.data(), random.size()); }
                catch (...) { throw Error(Failure::local_failure, "Could not identify the current clock session."); }
                return "process-" + detail::b64(random.data(), random.size());
            }
        };

        void zeroSecret(unsigned char* data, std::size_t length) noexcept
        {
            // A volatile sink keeps the wipe from being optimized away.
            volatile unsigned char* cursor = data;
            for (std::size_t index = 0; index < length; ++index) cursor[index] = 0;
        }

        int ueccRandom(unsigned char* destination, unsigned size)
        {
            try { crypto::random(destination, size); return 1; }
            catch (...) { return 0; }
        }

        void installUeccRandomOnce()
        {
            // uECC draws the per-signature nonce from this CSPRNG; never its
            // platform default, so behavior matches the other Nightflyer ports.
            static const auto installed = [] { uECC_set_rng(&ueccRandom); return true; }();
            (void)installed;
        }

        // Portable P-256 installation key over vendored micro-ecc. Used for
        // memory-only sessions on every platform and for persistent sessions
        // on platforms without a platform key-store adapter.
        class UeccInstallationKey final : public InstallationKey::Impl
        {
        public:
            UeccInstallationKey(const std::array<unsigned char, 32>& scalar, const std::array<unsigned char, 64>& coordinates)
                : scalar_(scalar), coordinates_(coordinates) {}
            ~UeccInstallationKey() override { zeroSecret(scalar_.data(), scalar_.size()); }
            UeccInstallationKey(const UeccInstallationKey&) = delete;
            UeccInstallationKey& operator=(const UeccInstallationKey&) = delete;

            std::array<unsigned char, 64> publicCoordinates() const override { return coordinates_; }

            std::array<unsigned char, 64> signSha256(std::string_view input) const override
            {
                installUeccRandomOnce();
                const auto digest = crypto::sha256(input);
                std::array<unsigned char, 64> signature{};
                if (uECC_sign(scalar_.data(), digest.data(), static_cast<unsigned>(digest.size()), signature.data(), uECC_secp256r1()) == 0)
                    throw Error(Failure::local_failure, "Installation proof signing failed.");
                return signature;
            }

            bool verifySha256(std::string_view input, const std::array<unsigned char, 64>& signature) const override
            {
                const auto digest = crypto::sha256(input);
                return uECC_verify(coordinates_.data(), digest.data(), static_cast<unsigned>(digest.size()), signature.data(), uECC_secp256r1()) != 0;
            }

            std::string exportPrivateKey() const override { return detail::b64(scalar_.data(), scalar_.size()); }

        private:
            std::array<unsigned char, 32> scalar_;
            std::array<unsigned char, 64> coordinates_;
        };

        bool littleEndianLess(const unsigned char* value, const std::array<unsigned char, 32>& limit)
        {
            for (std::size_t i = limit.size(); i-- > 0;)
            {
                if (value[i] < limit[i]) return true;
                if (value[i] > limit[i]) return false;
            }
            return false;
        }

        bool strictEd25519Point(const unsigned char* encoded)
        {
            static constexpr std::array<unsigned char, 32> fieldPrime{
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
            static constexpr std::array<std::array<unsigned char, 32>, 5> smallOrderY{{
                {},
                {0x01},
                {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
                 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
                {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
                 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
                {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
            }};

            std::array<unsigned char, 32> y{};
            std::copy_n(encoded, y.size(), y.begin());
            y.back() &= 0x7f;
            if (!littleEndianLess(y.data(), fieldPrime)) return false;
            // The vendored verifier rejects off-curve points but not the small
            // subgroup. Reject every canonical torsion encoding, including
            // sign-bit variants, before asking it to verify the equation.
            return std::none_of(smallOrderY.begin(), smallOrderY.end(), [&](const auto& point) {
                return crypto::fixedTimeEqual(y.data(), point.data(), y.size());
            });
        }

        bool canonicalEd25519Scalar(const unsigned char* encoded)
        {
            static constexpr std::array<unsigned char, 32> groupOrder{
                0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
            return littleEndianLess(encoded, groupOrder);
        }

        bool verifyEd25519(const std::vector<unsigned char>& key, std::string_view input, const std::vector<unsigned char>& signature)
        {
            if (key.size() != 32 || signature.size() != 64 || !strictEd25519Point(key.data())
                || !strictEd25519Point(signature.data()) || !canonicalEd25519Scalar(signature.data() + 32)) return false;
            // Raw construction only checks encoding length; the strict checks
            // above already rejected low-order and non-canonical points so the
            // vendored verifier only needs to confirm the signing equation.
            return ed25519_verify(signature.data(), reinterpret_cast<const unsigned char*>(input.data()), input.size(), key.data()) == 1;
        }

        std::string jsonString(const std::string& value)
        {
            try { return json(value).dump(-1, ' ', false, json::error_handler_t::strict); }
            catch (const json::exception&) { throw Error(Failure::configuration, "A request string is not valid UTF-8."); }
        }

        std::size_t utf8Length(const std::string& value)
        {
            (void)jsonString(value);
            return value.size();
        }

        Problem parseProblem(const json& value, long httpStatus)
        {
            detail::exact(value, {"type", "title", "status", "detail", "code"}, "problem", Failure::invalid_response);
            const auto status = detail::integer(value, "status", Failure::invalid_response);
            if (status < 100 || status > 599) throw Error(Failure::invalid_response, "Problem Details status is invalid.");
            Problem result{detail::text(value, "type", Failure::invalid_response), detail::text(value, "title", Failure::invalid_response), static_cast<long>(status), detail::text(value, "detail", Failure::invalid_response), detail::text(value, "code", Failure::invalid_response)};
            static const std::regex code("^[A-Z][A-Z0-9_]{0,63}$");
            if (result.status != httpStatus || result.type != "about:blank" || !std::regex_match(result.code, code))
                throw Error(Failure::invalid_response, "Problem Details framing is invalid.");
            return result;
        }
    }

    std::shared_ptr<IClock> systemClock()
    {
        static auto value = std::make_shared<SystemClock>();
        return value;
    }

    std::optional<std::chrono::seconds> HttpResponse::retryAfter() const
    {
        auto found = headers.find("retry-after");
        if (found == headers.end()) found = headers.find("Retry-After");
        if (found == headers.end()) return {};
        std::int64_t seconds = 0;
        const auto* begin = found->second.data();
        const auto* end = begin + found->second.size();
        const auto parsed = std::from_chars(begin, end, seconds);
        if (parsed.ec != std::errc{} || parsed.ptr != end || seconds < 0 || seconds > 86400) return {};
        return std::chrono::seconds(seconds);
    }

    InstallationKey::InstallationKey(std::unique_ptr<Impl> impl) : impl_(std::move(impl))
    {
        if (!impl_) throw Error(Failure::configuration, "Installation key implementation is missing.");
    }
    InstallationKey::~InstallationKey() = default;
    InstallationKey::InstallationKey(InstallationKey&&) noexcept = default;
    InstallationKey& InstallationKey::operator=(InstallationKey&&) noexcept = default;

    InstallationKey InstallationKey::ephemeral()
    {
        installUeccRandomOnce();
        std::array<unsigned char, 32> scalar{};
        std::array<unsigned char, 64> coordinates{};
        for (;;)
        {
            try { crypto::random(scalar.data(), scalar.size()); }
            catch (...) { throw Error(Failure::local_failure, "P-256 installation key generation failed."); }
            // Reject the negligible probability of an invalid scalar up front so
            // every accepted key has a well-defined public point.
            if (uECC_compute_public_key(scalar.data(), coordinates.data(), uECC_secp256r1()) != 0
                && uECC_valid_public_key(coordinates.data(), uECC_secp256r1()) != 0)
                break;
        }
        return InstallationKey(std::make_unique<UeccInstallationKey>(scalar, coordinates));
    }

    InstallationKey InstallationKey::fromPrivateKey(std::string_view encoded)
    {
        if (encoded.empty() || encoded.size() > 256) throw Error(Failure::configuration, "Installation key material is invalid.");
        auto scalarVector = detail::unb64(std::string(encoded), 32, Failure::configuration);
        std::array<unsigned char, 32> scalar{};
        std::copy(scalarVector.begin(), scalarVector.end(), scalar.begin());
        zeroSecret(scalarVector.data(), scalarVector.size());
        std::array<unsigned char, 64> coordinates{};
        if (uECC_compute_public_key(scalar.data(), coordinates.data(), uECC_secp256r1()) == 0
            || uECC_valid_public_key(coordinates.data(), uECC_secp256r1()) == 0)
            throw Error(Failure::configuration, "Installation key material is not a valid P-256 private key.");
        return InstallationKey(std::make_unique<UeccInstallationKey>(scalar, coordinates));
    }

    std::string InstallationKey::publicJwk() const
    {
        const auto coordinates = impl_->publicCoordinates();
        return json{{"crv", "P-256"}, {"kty", "EC"}, {"x", detail::b64(coordinates.data(), 32)}, {"y", detail::b64(coordinates.data() + 32, 32)}}.dump();
    }
    std::string InstallationKey::thumbprint() const { return detail::sha256(publicJwk()); }
    std::string InstallationKey::toPrivateKey() const { return impl_->exportPrivateKey(); }

    struct Client::Impl
    {
        struct Verified { json claims; std::string kid; };

        Config config;
        InstallationKey key;
        std::shared_ptr<IHttpClient> http;
        std::map<std::string, std::vector<unsigned char>> keys;
        std::string requestOrigin;
        std::string issuerOrigin;

        Impl(Config value, InstallationKey installationKey, std::shared_ptr<IHttpClient> transport)
            : config(std::move(value)), key(std::move(installationKey)), http(std::move(transport))
        {
            if (!detail::isSystemId(config.systemId)) throw Error(Failure::configuration, "System ID must contain exactly 20 ASCII alphanumeric characters.");
            requestOrigin = detail::origin(config.baseUrl, "baseUrl");
            issuerOrigin = detail::origin(config.expectedIssuer, "expectedIssuer");
            config.baseUrl = requestOrigin;
            config.expectedIssuer = issuerOrigin;
            if (utf8Length(config.sdkVersion) < 1 || utf8Length(config.sdkVersion) > 64 || config.timeout <= std::chrono::milliseconds::zero()
                || config.idempotentTransportRetries < 0 || config.idempotentTransportRetries > 5 || config.installationLockTimeout < std::chrono::milliseconds::zero() || !config.clock)
                throw Error(Failure::configuration, "Nightflyer configuration is invalid.");
            for (const auto& [kid, encoded] : config.trustedSigningKeys)
            {
                if (!detail::isKid(kid)) throw Error(Failure::configuration, "Every trusted signing key ID must be a 26-character Crockford ULID.");
                keys.emplace(kid, detail::unb64(encoded, 32, Failure::configuration));
            }
            if (keys.empty()) throw Error(Failure::configuration, "At least one pinned signing key is required.");
            // A null transport is allowed at construction so local-only
            // sessions (load/persist/forget) work; the first network call
            // then fails with an explicit configuration error.
        }

        static void validateText(const json& request, const char* name, std::size_t minimum, std::size_t maximum)
        {
            const auto value = detail::text(request, name, Failure::configuration);
            if (utf8Length(value) < minimum || utf8Length(value) > maximum) throw Error(Failure::configuration, std::string(name) + " has an invalid length.");
        }

        void validateRequest(const std::string& endpoint, const json& request, std::uint64_t keysetSequence, std::uint64_t statusSequence) const
        {
            if (keysetSequence > detail::maximumSafeInteger || statusSequence > detail::maximumSafeInteger) throw Error(Failure::configuration, "Sequence high-water mark is outside the supported range.");
            if (endpoint == "authorize")
            {
                validateText(request, "identity_type", 3, 7); validateText(request, "version", 0, 128); validateText(request, "digest", 0, 512);
                validateText(request, "sl_hwid", 1, 1024); validateText(request, "storage_mode", 6, 10);
                const auto seconds = detail::integer(request, "requested_offline_seconds", Failure::configuration);
                if (seconds < 1200 || seconds > 7776000) throw Error(Failure::configuration, "requestedOfflineSeconds must be between 1200 and 7776000.");
                if (detail::text(request, "identity_type", Failure::configuration) == "key") validateText(request, "license_key", 1, 160);
                else { validateText(request, "username", 1, 191); validateText(request, "password", 1, 4096); }
            }
            else
            {
                validateText(request, "lease", 1, 32768);
                if (endpoint == "renew") { validateText(request, "version", 0, 128); validateText(request, "digest", 0, 512); validateText(request, "sl_hwid", 1, 1024); }
                if (endpoint == "end") validateText(request, "end_reason", 1, 128);
            }
        }

        static json projection(const std::string& endpoint, const json& request)
        {
            std::vector<std::string> names;
            if (endpoint == "authorize") names = {"protocol_version", "sdk_version", "system", "identity_type", "version", "digest", "sl_hwid", "storage_mode", "requested_offline_seconds", "trusted_kids", "keyset_sequence", "status_sequence"};
            else if (endpoint == "renew") names = {"protocol_version", "sdk_version", "system", "version", "digest", "sl_hwid", "trusted_kids", "keyset_sequence", "status_sequence"};
            else if (endpoint == "status") names = {"protocol_version", "sdk_version", "system", "trusted_kids", "keyset_sequence", "status_sequence"};
            else if (endpoint == "end") names = {"protocol_version", "sdk_version", "system", "end_reason", "trusted_kids", "keyset_sequence", "status_sequence"};
            else throw Error(Failure::local_failure, "Unknown Nightflyer endpoint.");
            json result = json::object();
            for (const auto& name : names) result[name] = request.at(name);
            return result;
        }

        std::string proof(const std::string& endpoint, const json& requestProjection, const std::optional<std::string>& lease, const std::string& jti) const
        {
            const auto htu = issuerOrigin + "/api/nightflyer/v1/" + endpoint;
            const json header{{"alg", "ES256"}, {"typ", "nightflyer-proof+jwt"}, {"jwk", detail::strictJson(key.publicJwk(), Failure::local_failure, "Installation JWK is invalid.")}};
            json claims{{"nightflyer_version", 1}, {"htm", "POST"}, {"htu", htu}, {"system", config.systemId}, {"iat", config.clock->unixSeconds()}, {"jti", jti}, {"rqh", detail::sha256(requestProjection.dump(-1, ' ', false, json::error_handler_t::strict))}};
            if (lease) claims["ath"] = detail::sha256(*lease);
            const auto headerText = header.dump();
            const auto encodedHeader = detail::b64(reinterpret_cast<const unsigned char*>(headerText.data()), headerText.size());
            const auto claimsText = claims.dump(-1, ' ', false, json::error_handler_t::strict);
            const auto encodedClaims = detail::b64(reinterpret_cast<const unsigned char*>(claimsText.data()), claimsText.size());
            const auto input = encodedHeader + "." + encodedClaims;
            const auto signature = key.impl_->signSha256(input);
            return input + "." + detail::b64(signature.data(), signature.size());
        }

        PreparedRequest prepare(std::string endpoint, json request, std::optional<std::string> lease, std::uint64_t keysetSequence, std::uint64_t statusSequence) const
        {
            validateRequest(endpoint, request, keysetSequence, statusSequence);
            request["protocol_version"] = 1; request["sdk_version"] = config.sdkVersion; request["system"] = config.systemId;
            request["trusted_kids"] = json::array();
            for (const auto& [kid, ignored] : keys) { (void)ignored; request["trusted_kids"].push_back(kid); }
            request["keyset_sequence"] = keysetSequence; request["status_sequence"] = statusSequence;
            std::array<unsigned char, 16> nonce{};
            try { crypto::random(nonce.data(), nonce.size()); }
            catch (...) { throw Error(Failure::local_failure, "CSPRNG failure."); }
            const auto jti = detail::b64(nonce.data(), nonce.size());
            std::optional<std::string> hwid;
            if (request.contains("sl_hwid")) hwid = request.at("sl_hwid").get<std::string>();
            auto body = request.dump(-1, ' ', false, json::error_handler_t::strict);
            auto compactProof = proof(endpoint, projection(endpoint, request), lease, jti);
            return {endpoint, requestOrigin + "/api/nightflyer/v1/" + endpoint, std::move(body), std::move(compactProof), jti, std::move(lease), std::move(hwid), keysetSequence, statusSequence};
        }

        Verified verifyJws(const std::string& compact, const char* type, const std::map<std::string, std::vector<unsigned char>>& trusted) const
        {
            const auto pieces = detail::compactParts(compact);
            const auto headerBytes = detail::unb64(pieces[0]);
            const auto header = detail::strictJson(std::string_view(reinterpret_cast<const char*>(headerBytes.data()), headerBytes.size()), Failure::invalid_token, "JWS header is not strict JSON.");
            detail::exact(header, {"alg", "kid", "typ"}, "JWS header");
            const auto kid = detail::text(header, "kid");
            if (detail::text(header, "alg") != "EdDSA" || detail::text(header, "typ") != type || !detail::isKid(kid)) throw Error(Failure::invalid_token, "Unexpected signed token profile.");
            const auto found = trusted.find(kid);
            if (found == trusted.end()) throw Error(Failure::invalid_token, "Token signing key is not trusted.");
            if (!verifyEd25519(found->second, pieces[0] + "." + pieces[1], detail::unb64(pieces[2], 64))) throw Error(Failure::invalid_signature, "Nightflyer signature verification failed.");
            const auto claimBytes = detail::unb64(pieces[1]);
            auto claims = detail::strictJson(std::string_view(reinterpret_cast<const char*>(claimBytes.data()), claimBytes.size()), Failure::invalid_token, "JWS claims are not strict JSON.");
            if (!claims.is_object() || detail::text(claims, "iss") != config.expectedIssuer) throw Error(Failure::invalid_token, "Token issuer is not trusted.");
            return {std::move(claims), kid};
        }

        void audience(const json& claims) const
        {
            if (detail::text(claims, "aud") != config.systemId || detail::integer(claims, "nightflyer_version") != 1) throw Error(Failure::invalid_token, "Signed object audience or protocol version is invalid.");
        }

        Lease verifyLease(const std::string& compact, const std::optional<std::string>& requestJti, const std::optional<std::string>& hwid, const std::map<std::string, std::vector<unsigned char>>& trusted) const
        {
            const auto verified = verifyJws(compact, "nightflyer-auth+jwt", trusted);
            const auto& claims = verified.claims;
            detail::exact(claims, {"iss", "sub", "aud", "jti", "nightflyer_version", "device_id", "cnf", "sl_hwid_sha256", "generation", "iat", "nbf", "exp", "renew_after", "policy_revision", "request_jti", "entitlements"}, "lease");
            audience(claims);
            detail::unb64(detail::text(claims, "sub"), 32);
            const auto authorizationId = detail::text(claims, "jti");
            const auto deviceId = detail::text(claims, "device_id");
            if (!detail::isUuidV4(authorizationId) || !detail::isUuidV4(deviceId)) throw Error(Failure::invalid_token, "Lease identifiers are invalid.");
            const auto tokenJti = detail::text(claims, "request_jti"); detail::unb64(tokenJti, 16);
            if (requestJti && !detail::fixedEqual(tokenJti, *requestJti)) throw Error(Failure::invalid_token, "Lease does not bind to this request.");
            const auto& confirmation = claims.at("cnf"); detail::exact(confirmation, {"jkt"}, "lease confirmation");
            const auto thumbprint = detail::text(confirmation, "jkt"); detail::unb64(thumbprint, 32);
            if (!detail::fixedEqual(thumbprint, key.thumbprint())) throw Error(Failure::invalid_token, "Lease belongs to another installation.");
            const auto hwidHash = detail::text(claims, "sl_hwid_sha256"); detail::unb64(hwidHash, 32);
            if (hwid && !detail::fixedEqual(hwidHash, detail::sha256(*hwid))) throw Error(Failure::invalid_token, "Lease belongs to another hardware identity.");
            const auto generation = detail::safePositive(claims, "generation");
            (void)detail::safePositive(claims, "policy_revision");
            const auto issued = detail::timestamp(claims, "iat"); const auto notBefore = detail::timestamp(claims, "nbf");
            const auto expires = detail::timestamp(claims, "exp"); const auto renewAfter = detail::timestamp(claims, "renew_after");
            if (notBefore != issued || renewAfter < issued || renewAfter >= expires || expires <= issued || expires - issued > 7776000) throw Error(Failure::invalid_token, "Lease timestamps are invalid.");
            if (!claims.at("entitlements").is_object() || !claims.at("entitlements").empty()) throw Error(Failure::invalid_token, "Lease entitlements use an unsupported profile.");
            return {compact, authorizationId, generation, issued, expires, renewAfter, thumbprint, deviceId, hwidHash, verified.kid};
        }

        Status verifyStatus(const std::string& compact, const std::optional<std::string>& requestJti, const std::optional<Lease>& lease, const std::map<std::string, std::vector<unsigned char>>& trusted) const
        {
            const auto verified = verifyJws(compact, "nightflyer-status+jwt", trusted);
            const auto& claims = verified.claims;
            detail::exact(claims, {"iss", "aud", "nightflyer_version", "device_id", "authorization_id", "status_sequence", "keyset_sequence", "minimum_generation", "device_status", "grant_status", "revoked_kids", "iat", "next_update", "request_jti"}, "status");
            audience(claims);
            const auto tokenJti = detail::text(claims, "request_jti"); detail::unb64(tokenJti, 16);
            if (requestJti && !detail::fixedEqual(tokenJti, *requestJti)) throw Error(Failure::invalid_token, "Status does not bind to this request.");
            const auto authorizationId = detail::text(claims, "authorization_id"); const auto deviceId = detail::text(claims, "device_id");
            if (!detail::isUuidV4(authorizationId) || !detail::isUuidV4(deviceId)) throw Error(Failure::invalid_token, "Status identifiers are invalid.");
            if (lease && (!detail::fixedEqual(authorizationId, lease->authorizationId) || !detail::fixedEqual(deviceId, lease->deviceId))) throw Error(Failure::invalid_token, "Status belongs to another lease or device.");
            Status result; result.compact = compact; result.authorizationId = authorizationId; result.deviceId = deviceId;
            result.sequence = detail::safeNonnegative(claims, "status_sequence"); result.keysetSequence = detail::safeNonnegative(claims, "keyset_sequence"); result.minimumGeneration = detail::safePositive(claims, "minimum_generation");
            result.deviceStatus = detail::text(claims, "device_status"); result.grantStatus = detail::text(claims, "grant_status");
            if ((result.deviceStatus != "active" && result.deviceStatus != "revoked") || (result.grantStatus != "active" && result.grantStatus != "reclaim_pending" && result.grantStatus != "ended" && result.grantStatus != "revoked")) throw Error(Failure::invalid_token, "Status state is invalid.");
            const auto& revoked = claims.at("revoked_kids");
            if (!revoked.is_array()) throw Error(Failure::invalid_token, "Status revocation list is invalid.");
            std::string previous;
            for (const auto& value : revoked)
            {
                if (!value.is_string() || !detail::isKid(value.get<std::string>()) || (!previous.empty() && previous >= value.get<std::string>())) throw Error(Failure::invalid_token, "Status revocation list is not strictly sorted.");
                previous = value.get<std::string>(); result.revokedSigningKeyIds.push_back(previous);
            }
            result.issuedAt = detail::timestamp(claims, "iat");
            if (claims.at("next_update").is_null()) result.nextUpdate.reset();
            else result.nextUpdate = detail::timestamp(claims, "next_update");
            return result;
        }

        Decision verifyDecision(const std::string& compact, const std::string& requestJti, const std::optional<Lease>& lease, const std::optional<Status>& status, const std::map<std::string, std::vector<unsigned char>>& trusted) const
        {
            const auto verified = verifyJws(compact, "nightflyer-decision+jwt", trusted);
            const auto& claims = verified.claims; audience(claims);
            Decision result; result.compact = compact; result.responseCode = detail::text(claims, "response_code");
            static const std::regex code("^[A-Z][A-Z0-9_]{0,63}$"); if (!std::regex_match(result.responseCode, code)) throw Error(Failure::invalid_token, "Decision response code is invalid.");
            const auto tokenJti = detail::text(claims, "request_jti"); detail::unb64(tokenJti, 16); if (!detail::fixedEqual(tokenJti, requestJti)) throw Error(Failure::invalid_token, "Decision does not bind to this request.");
            result.issuedAt = detail::timestamp(claims, "iat"); result.leaseDisposition = detail::text(claims, "lease_disposition");
            if (result.leaseDisposition != "unchanged" && result.leaseDisposition != "revoked" && result.leaseDisposition != "ended" && result.leaseDisposition != "expired") throw Error(Failure::invalid_token, "Decision lease disposition is invalid.");
            const bool hasId = claims.contains("device_id"), hasJkt = claims.contains("device_jkt");
            if (hasId == hasJkt) throw Error(Failure::invalid_token, "Decision must contain exactly one device binding.");
            if (hasId)
            {
                result.deviceId = detail::text(claims, "device_id"); if (!detail::isUuidV4(*result.deviceId)) throw Error(Failure::invalid_token, "Decision device ID is invalid.");
                const auto expected = status ? std::optional<std::string>(status->deviceId) : (lease ? std::optional<std::string>(lease->deviceId) : std::nullopt);
                if (!expected || !detail::fixedEqual(*expected, *result.deviceId)) throw Error(Failure::invalid_token, "Decision belongs to another device.");
            }
            else
            {
                result.deviceThumbprint = detail::text(claims, "device_jkt"); detail::unb64(*result.deviceThumbprint, 32);
                if (!detail::fixedEqual(*result.deviceThumbprint, key.thumbprint())) throw Error(Failure::invalid_token, "Decision belongs to another installation.");
            }
            if (claims.contains("occupancy_released"))
            {
                if (!claims.at("occupancy_released").is_boolean()) throw Error(Failure::invalid_token, "Decision occupancy result is invalid.");
                result.occupancyReleased = claims.at("occupancy_released").get<bool>();
            }
            if (result.responseCode == "PROTOCOL_UPGRADE_REQUIRED")
            {
                result.minimumProtocolVersion = detail::safePositive(claims, "minimum_protocol_version"); result.latestProtocolVersion = detail::safePositive(claims, "latest_protocol_version");
                result.minimumSdkVersion = detail::text(claims, "minimum_sdk_version"); result.updateUrl = detail::text(claims, "update_url");
                if (result.updateUrl->rfind("https://", 0) != 0) throw Error(Failure::invalid_token, "Decision update URL is invalid.");
            }
            std::vector<std::string> fields{"iss", "aud", "nightflyer_version", "response_code", hasId ? "device_id" : "device_jkt", "request_jti", "iat", "lease_disposition"};
            if (result.occupancyReleased) fields.push_back("occupancy_released");
            if (result.responseCode == "PROTOCOL_UPGRADE_REQUIRED") fields.insert(fields.end(), {"minimum_protocol_version", "latest_protocol_version", "minimum_sdk_version", "update_url"});
            detail::exact(claims, fields, "decision");
            return result;
        }

        std::uint64_t transition(const std::string& compact, std::uint64_t previous, std::map<std::string, std::vector<unsigned char>>& trusted) const
        {
            const auto verified = verifyJws(compact, "nightflyer-keyset+jwt", trusted); const auto& claims = verified.claims;
            detail::exact(claims, {"iss", "aud", "nightflyer_version", "old_kid", "new_kid", "new_key", "iat", "keyset_sequence"}, "key transition"); audience(claims);
            const auto oldKid = detail::text(claims, "old_kid"), newKid = detail::text(claims, "new_kid");
            if (!detail::isKid(oldKid) || !detail::isKid(newKid) || !detail::fixedEqual(oldKid, verified.kid)) throw Error(Failure::invalid_token, "Key transition identifiers are invalid.");
            (void)detail::timestamp(claims, "iat"); const auto sequence = detail::safePositive(claims, "keyset_sequence"); if (sequence <= previous) throw Error(Failure::invalid_token, "Key transition sequence did not advance.");
            const auto& newKey = claims.at("new_key"); detail::exact(newKey, {"kty", "crv", "x"}, "transition key");
            if (detail::text(newKey, "kty") != "OKP" || detail::text(newKey, "crv") != "Ed25519") throw Error(Failure::invalid_token, "Transition key profile is invalid.");
            const auto decoded = detail::unb64(detail::text(newKey, "x"), 32); const auto found = trusted.find(newKid);
            if (found != trusted.end() && (found->second.size() != decoded.size() || !crypto::fixedTimeEqual(found->second.data(), decoded.data(), decoded.size()))) throw Error(Failure::invalid_token, "Transition changes an existing key ID.");
            trusted[newKid] = decoded; return sequence;
        }

        Response process(const HttpResponse& raw, const PreparedRequest& request)
        {
            if (!raw.error.empty()) throw Error(Failure::transport, raw.error);
            if (raw.body.empty() || raw.body.size() > 1048576) throw Error(Failure::invalid_response, "Nightflyer response body is missing or too large.");
            const auto outer = detail::strictJson(raw.body, Failure::invalid_response, "Nightflyer response is not strict JSON.");
            if (!outer.is_object()) throw Error(Failure::invalid_response, "Nightflyer response must be an object.");
            if (!outer.contains("protocol_version"))
            {
                if (raw.status >= 200 && raw.status < 300) throw Error(Failure::invalid_response, "Successful response lacks Nightflyer framing.");
                return {raw.status, {}, {}, {}, parseProblem(outer, raw.status), {}, request.keysetSequence, raw.retryAfter()};
            }
            if (detail::integer(outer, "protocol_version", Failure::invalid_response) != 1 || !detail::fixedEqual(detail::text(outer, "request_jti", Failure::invalid_response), request.requestJti)) throw Error(Failure::invalid_response, "Response does not bind to this request.");
            detail::unb64(request.requestJti, 16, Failure::invalid_response);
            std::vector<std::string> outerFields{"protocol_version", "request_jti", "key_transitions"};
            for (const auto* optional : {"lease", "status", "decision", "problem"}) if (outer.contains(optional)) outerFields.emplace_back(optional);
            detail::exact(outer, outerFields, "response", Failure::invalid_response);
            if (!outer.at("key_transitions").is_array()) throw Error(Failure::invalid_response, "Nightflyer framing lacks key_transitions.");

            auto working = keys; Response response; response.httpStatus = raw.status; response.keysetSequence = request.keysetSequence; response.retryAfter = raw.retryAfter();
            for (const auto& value : outer.at("key_transitions"))
            {
                if (!value.is_string()) throw Error(Failure::invalid_response, "Key transition is not a compact JWS.");
                const auto compact = value.get<std::string>(); response.keysetSequence = transition(compact, response.keysetSequence, working); response.keyTransitions.push_back(compact);
            }
            std::optional<Lease> presented;
            if (request.presentedLease) presented = verifyLease(*request.presentedLease, {}, request.expectedHwid, working);
            if (outer.contains("lease"))
            {
                if (!outer.at("lease").is_string()) throw Error(Failure::invalid_response, "Response lease is not a compact JWS.");
                response.lease = verifyLease(outer.at("lease").get<std::string>(), request.requestJti, request.expectedHwid, working);
            }
            if (outer.contains("status"))
            {
                if (!outer.at("status").is_string()) throw Error(Failure::invalid_response, "Response status is not a compact JWS.");
                response.status = verifyStatus(outer.at("status").get<std::string>(), request.requestJti, response.lease ? response.lease : presented, working);
                if (response.status->sequence < request.statusSequence || response.status->keysetSequence < response.keysetSequence) throw Error(Failure::invalid_token, "Signed status moved behind a client high-water mark.");
                response.keysetSequence = std::max(response.keysetSequence, response.status->keysetSequence);
            }
            if (outer.contains("decision"))
            {
                if (!outer.at("decision").is_string()) throw Error(Failure::invalid_response, "Response decision is not a compact JWS.");
                response.decision = verifyDecision(outer.at("decision").get<std::string>(), request.requestJti, response.lease ? response.lease : presented, response.status, working);
            }
            if (outer.contains("problem")) response.problem = parseProblem(outer.at("problem"), raw.status);
            if (response.success() && !response.status) throw Error(Failure::invalid_response, "Successful Nightflyer response requires signed status.");
            if (!response.success() && (!response.decision || !response.problem)) throw Error(Failure::invalid_response, "Framed denial requires a signed decision and Problem Details.");
            keys = std::move(working);
            return response;
        }

        Response send(const PreparedRequest& request)
        {
            if (!http) throw Error(Failure::configuration, "An HTTP transport is required; pass UnrealHttpTransport (engine) or your own IHttpClient.");
            auto raw = http->postJson(request.url, request.body, request.proof);
            for (int attempt = 0; !raw.error.empty() && attempt < config.idempotentTransportRetries; ++attempt) raw = http->postJson(request.url, request.body, request.proof);
            return process(raw, request);
        }
    };

    Client::Client(Config config, InstallationKey key, std::shared_ptr<IHttpClient> http) : impl_(std::make_unique<Impl>(std::move(config), std::move(key), std::move(http))) {}
    Client::~Client() = default; Client::Client(Client&&) noexcept = default; Client& Client::operator=(Client&&) noexcept = default;

    Response Client::authorizeWithKey(std::string licenseKey, std::string version, std::string digest, std::string slHwid, int seconds, bool persistent, std::uint64_t keyset, std::uint64_t status)
    {
        return impl_->send(impl_->prepare("authorize", json{{"identity_type", "key"}, {"license_key", std::move(licenseKey)}, {"version", std::move(version)}, {"digest", std::move(digest)}, {"sl_hwid", std::move(slHwid)}, {"storage_mode", persistent ? "persistent" : "memory"}, {"requested_offline_seconds", seconds}}, {}, keyset, status));
    }
    Response Client::authorizeWithAccount(std::string username, std::string password, std::string version, std::string digest, std::string slHwid, int seconds, bool persistent, std::uint64_t keyset, std::uint64_t status)
    {
        return impl_->send(impl_->prepare("authorize", json{{"identity_type", "account"}, {"username", std::move(username)}, {"password", std::move(password)}, {"version", std::move(version)}, {"digest", std::move(digest)}, {"sl_hwid", std::move(slHwid)}, {"storage_mode", persistent ? "persistent" : "memory"}, {"requested_offline_seconds", seconds}}, {}, keyset, status));
    }
    Response Client::renew(std::string lease, std::string version, std::string digest, std::string slHwid, std::uint64_t keyset, std::uint64_t status)
    {
        auto request = impl_->prepare("renew", json{{"lease", lease}, {"version", std::move(version)}, {"digest", std::move(digest)}, {"sl_hwid", std::move(slHwid)}}, lease, keyset, status); return impl_->send(request);
    }
    Response Client::status(std::string lease, std::uint64_t keyset, std::uint64_t statusSequence)
    {
        auto request = impl_->prepare("status", json{{"lease", lease}}, lease, keyset, statusSequence); return impl_->send(request);
    }
    Response Client::end(std::string lease, std::string reason, std::uint64_t keyset, std::uint64_t statusSequence) { return sendPrepared(prepareEnd(std::move(lease), std::move(reason), keyset, statusSequence)); }
    PreparedRequest Client::prepareEnd(std::string lease, std::string reason, std::uint64_t keyset, std::uint64_t statusSequence) { return impl_->prepare("end", json{{"lease", lease}, {"end_reason", std::move(reason)}}, lease, keyset, statusSequence); }
    Response Client::sendPrepared(const PreparedRequest& request) { return impl_->send(request); }
    Lease Client::verifyCachedLease(const std::string& compact) const { return impl_->verifyLease(compact, {}, {}, impl_->keys); }
    Status Client::verifyCachedStatus(const std::string& compact, const std::optional<Lease>& lease) const { return impl_->verifyStatus(compact, {}, lease, impl_->keys); }
    std::map<std::string, std::string> Client::trustedSigningKeys() const
    {
        std::map<std::string, std::string> result; for (const auto& [kid, key] : impl_->keys) result.emplace(kid, detail::b64(key)); return result;
    }
    void Client::restoreTrustedSigningKeyTransitions(const std::vector<std::string>& transitions, std::uint64_t expectedSequence)
    {
        std::map<std::string, std::vector<unsigned char>> decoded;
        for (const auto& [kid, value] : impl_->config.trustedSigningKeys)
        {
            if (!detail::isKid(kid)) throw Error(Failure::invalid_state, "Configured signing key ID is invalid.");
            decoded.emplace(kid, detail::unb64(value, 32, Failure::invalid_state));
        }

        std::uint64_t sequence = 0;
        try
        {
            for (const auto& compact : transitions) sequence = impl_->transition(compact, sequence, decoded);
        }
        catch (const Error& error)
        {
            if (error.failure() != Failure::invalid_token && error.failure() != Failure::invalid_signature) throw;
            throw Error(Failure::invalid_state, "Persistent signing-key transition history is not authentic.");
        }
        if (sequence != expectedSequence) throw Error(Failure::invalid_state, "Persistent signing-key transition history does not match its high-water mark.");
        impl_->keys = std::move(decoded);
    }
    std::string Client::signPersistentState(std::string_view input) const
    {
        const auto signature = impl_->key.impl_->signSha256(input);
        return detail::b64(signature.data(), signature.size());
    }
    bool Client::verifyPersistentState(std::string_view input, const std::string& encoded) const
    {
        const auto decoded = detail::unb64(encoded, 64, Failure::invalid_state);
        std::array<unsigned char, 64> signature{};
        std::copy(decoded.begin(), decoded.end(), signature.begin());
        return impl_->key.impl_->verifySha256(input, signature);
    }
}
