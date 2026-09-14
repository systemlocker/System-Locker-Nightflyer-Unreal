#include "internal.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <array>

namespace syslocker::nightflyer
{
    namespace
    {
        void check(SECURITY_STATUS status, const char* message)
        {
            if (status != ERROR_SUCCESS) throw Error(Failure::local_failure, message);
        }

        std::wstring wide(std::string_view value)
        {
            if (value.empty()) return {};
            const auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
            if (length <= 0) throw Error(Failure::invalid_state, "CNG key reference is not valid UTF-8.");
            std::wstring result(static_cast<std::size_t>(length), L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), length) != length)
                throw Error(Failure::invalid_state, "CNG key reference is not valid UTF-8.");
            return result;
        }

        std::string narrow(std::wstring_view value)
        {
            const auto length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
            if (length <= 0) throw Error(Failure::local_failure, "CNG provider name is not valid UTF-8.");
            std::string result(static_cast<std::size_t>(length), '\0');
            if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), length, nullptr, nullptr) != length)
                throw Error(Failure::local_failure, "CNG provider name is not valid UTF-8.");
            return result;
        }

        class CngInstallationKey final : public InstallationKey::Impl
        {
        public:
            explicit CngInstallationKey(NCRYPT_KEY_HANDLE key) : key_(key) {}
            ~CngInstallationKey() override { if (key_) NCryptFreeObject(key_); }

            std::array<unsigned char, 64> publicCoordinates() const override
            {
                DWORD length = 0;
                check(NCryptExportKey(key_, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &length, 0), "Could not read the CNG installation public key.");
                std::vector<unsigned char> blob(length);
                check(NCryptExportKey(key_, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, blob.data(), length, &length, 0), "Could not read the CNG installation public key.");
                if (blob.size() != sizeof(BCRYPT_ECCKEY_BLOB) + 64) throw Error(Failure::local_failure, "CNG installation key is not P-256.");
                const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());
                if (header->dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || header->cbKey != 32) throw Error(Failure::local_failure, "CNG installation key is not P-256.");
                std::array<unsigned char, 64> result{};
                std::copy(blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), blob.end(), result.begin());
                return result;
            }

            std::array<unsigned char, 64> signSha256(std::string_view input) const override
            {
                std::array<unsigned char, 32> hash{};
                BCRYPT_ALG_HANDLE algorithm = nullptr;
                BCRYPT_HASH_HANDLE hashing = nullptr;
                DWORD objectLength = 0, returned = 0;
                if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0
                    || BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &returned, 0) != 0)
                {
                    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
                    throw Error(Failure::local_failure, "SHA-256 setup failed for the CNG installation key.");
                }
                std::vector<unsigned char> object(objectLength);
                if (BCryptCreateHash(algorithm, &hashing, object.data(), objectLength, nullptr, 0, 0) != 0
                    || BCryptHashData(hashing, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())), static_cast<ULONG>(input.size()), 0) != 0
                    || BCryptFinishHash(hashing, hash.data(), static_cast<ULONG>(hash.size()), 0) != 0)
                {
                    if (hashing) BCryptDestroyHash(hashing);
                    BCryptCloseAlgorithmProvider(algorithm, 0);
                    throw Error(Failure::local_failure, "SHA-256 failed for the CNG installation key.");
                }
                BCryptDestroyHash(hashing); BCryptCloseAlgorithmProvider(algorithm, 0);
                std::array<unsigned char, 64> signature{}; DWORD length = 0;
                check(NCryptSignHash(key_, nullptr, hash.data(), static_cast<DWORD>(hash.size()), signature.data(), static_cast<DWORD>(signature.size()), &length, 0), "CNG installation proof signing failed.");
                if (length != signature.size()) throw Error(Failure::local_failure, "CNG returned a non-P256 signature.");
                SecureZeroMemory(hash.data(), hash.size());
                return signature;
            }

            bool verifySha256(std::string_view input, const std::array<unsigned char, 64>& signature) const override
            {
                std::array<unsigned char, 32> hash{};
                BCRYPT_ALG_HANDLE algorithm = nullptr;
                BCRYPT_HASH_HANDLE hashing = nullptr;
                DWORD objectLength = 0, returned = 0;
                if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0
                    || BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &returned, 0) != 0)
                {
                    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
                    throw Error(Failure::local_failure, "SHA-256 setup failed for CNG state verification.");
                }
                std::vector<unsigned char> object(objectLength);
                if (BCryptCreateHash(algorithm, &hashing, object.data(), objectLength, nullptr, 0, 0) != 0
                    || BCryptHashData(hashing, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())), static_cast<ULONG>(input.size()), 0) != 0
                    || BCryptFinishHash(hashing, hash.data(), static_cast<ULONG>(hash.size()), 0) != 0)
                {
                    if (hashing) BCryptDestroyHash(hashing);
                    BCryptCloseAlgorithmProvider(algorithm, 0);
                    throw Error(Failure::local_failure, "SHA-256 failed for CNG state verification.");
                }
                BCryptDestroyHash(hashing); BCryptCloseAlgorithmProvider(algorithm, 0);
                const auto result = NCryptVerifySignature(key_, nullptr, hash.data(), static_cast<DWORD>(hash.size()),
                    const_cast<unsigned char*>(signature.data()), static_cast<DWORD>(signature.size()), 0);
                SecureZeroMemory(hash.data(), hash.size());
                if (result == ERROR_SUCCESS) return true;
                if (result == NTE_BAD_SIGNATURE) return false;
                throw Error(Failure::local_failure, "CNG installation state signature verification failed.");
            }

            std::string exportPrivateKey() const override { throw Error(Failure::local_failure, "Non-exportable CNG installation keys cannot be exported."); }
        private:
            NCRYPT_KEY_HANDLE key_;
        };

        class CngProvider final : public IInstallationKeyProvider
        {
        public:
            InstallationKeyHandle create(std::string_view systemId) override
            {
                const auto name = "SystemLocker.Nightflyer." + std::string(systemId) + "." + randomSuffix();
                return createNamed(name);
            }

            InstallationKeyHandle load(std::string_view systemId, std::string_view reference) override
            {
                const auto parsed = parse(systemId, reference);
                NCRYPT_PROV_HANDLE provider = 0; NCRYPT_KEY_HANDLE key = 0;
                const auto providerName = wide(parsed.first), keyName = wide(parsed.second);
                if (NCryptOpenStorageProvider(&provider, providerName.c_str(), 0) != ERROR_SUCCESS
                    || NCryptOpenKey(provider, &key, keyName.c_str(), 0, 0) != ERROR_SUCCESS)
                {
                    if (key) NCryptFreeObject(key); if (provider) NCryptFreeObject(provider);
                    throw Error(Failure::invalid_state, "Persistent CNG installation key is unavailable.");
                }
                NCryptFreeObject(provider);
                return {std::string(reference), InstallationKey(std::make_unique<CngInstallationKey>(key))};
            }

            InstallationKeyHandle openOrCreateStable(std::string_view systemId) override
            {
                const auto name = "SystemLocker.Nightflyer." + std::string(systemId) + ".memory";
                for (const auto* provider : {MS_PLATFORM_CRYPTO_PROVIDER, MS_KEY_STORAGE_PROVIDER})
                {
                    try { return openNamed(provider, name); } catch (const Error&) { }
                }
                return createNamed(name);
            }

            void erase(std::string_view systemId, std::string_view reference) override
            {
                const auto parsed = parse(systemId, reference);
                NCRYPT_PROV_HANDLE provider = 0; NCRYPT_KEY_HANDLE key = 0;
                const auto providerName = wide(parsed.first), keyName = wide(parsed.second);
                if (NCryptOpenStorageProvider(&provider, providerName.c_str(), 0) != ERROR_SUCCESS
                    || NCryptOpenKey(provider, &key, keyName.c_str(), 0, 0) != ERROR_SUCCESS
                    || NCryptDeleteKey(key, 0) != ERROR_SUCCESS)
                {
                    if (key) NCryptFreeObject(key); if (provider) NCryptFreeObject(provider);
                    throw Error(Failure::local_failure, "Persistent CNG installation key could not be deleted.");
                }
                NCryptFreeObject(provider);
            }

        private:
            static std::string randomSuffix()
            {
                GUID value{};
                if (CoCreateGuid(&value) != S_OK) throw Error(Failure::local_failure, "Could not allocate a CNG installation key name.");
                char result[33]{};
                std::snprintf(result, sizeof(result), "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x", value.Data1, value.Data2, value.Data3,
                    value.Data4[0], value.Data4[1], value.Data4[2], value.Data4[3], value.Data4[4], value.Data4[5], value.Data4[6], value.Data4[7]);
                return result;
            }

            static std::pair<std::string, std::string> parse(std::string_view systemId, std::string_view reference)
            {
                constexpr std::string_view prefix = "cng-v1:";
                if (!reference.starts_with(prefix)) throw Error(Failure::invalid_state, "Persistent CNG key reference is invalid.");
                const auto bytes = detail::unb64(std::string(reference.substr(prefix.size())), 0, Failure::invalid_state);
                const auto value = detail::strictJson(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()), Failure::invalid_state, "Persistent CNG key reference is invalid.");
                detail::exact(value, {"provider", "name"}, "CNG key reference", Failure::invalid_state);
                const auto provider = detail::text(value, "provider", Failure::invalid_state), name = detail::text(value, "name", Failure::invalid_state);
                if (!name.starts_with("SystemLocker.Nightflyer." + std::string(systemId) + ".")) throw Error(Failure::invalid_state, "Persistent CNG key belongs to another system.");
                return {provider, name};
            }

            static std::string reference(std::wstring_view provider, const std::string& name)
            {
                const auto value = detail::json{{"provider", narrow(provider)}, {"name", name}}.dump();
                return "cng-v1:" + detail::b64(reinterpret_cast<const unsigned char*>(value.data()), value.size());
            }

            static InstallationKeyHandle openNamed(const wchar_t* providerName, const std::string& name)
            {
                NCRYPT_PROV_HANDLE provider = 0; NCRYPT_KEY_HANDLE key = 0; const auto wideName = wide(name);
                if (NCryptOpenStorageProvider(&provider, providerName, 0) != ERROR_SUCCESS || NCryptOpenKey(provider, &key, wideName.c_str(), 0, 0) != ERROR_SUCCESS)
                {
                    if (key) NCryptFreeObject(key); if (provider) NCryptFreeObject(provider);
                    throw Error(Failure::invalid_state, "Named CNG installation key is unavailable.");
                }
                const auto resultReference = reference(providerName, name); NCryptFreeObject(provider);
                return {resultReference, InstallationKey(std::make_unique<CngInstallationKey>(key))};
            }

            static InstallationKeyHandle createNamed(const std::string& name)
            {
                for (const auto* providerName : {MS_PLATFORM_CRYPTO_PROVIDER, MS_KEY_STORAGE_PROVIDER})
                {
                    NCRYPT_PROV_HANDLE provider = 0; NCRYPT_KEY_HANDLE key = 0; const auto wideName = wide(name);
                    if (NCryptOpenStorageProvider(&provider, providerName, 0) == ERROR_SUCCESS
                        && NCryptCreatePersistedKey(provider, &key, NCRYPT_ECDSA_P256_ALGORITHM, wideName.c_str(), 0, 0) == ERROR_SUCCESS)
                    {
                        DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
                        (void)NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof(usage), 0);
                        if (NCryptFinalizeKey(key, 0) == ERROR_SUCCESS)
                        {
                            const auto resultReference = reference(providerName, name); NCryptFreeObject(provider);
                            return {resultReference, InstallationKey(std::make_unique<CngInstallationKey>(key))};
                        }
                    }
                    if (key) NCryptFreeObject(key); if (provider) NCryptFreeObject(provider);
                    try { return openNamed(providerName, name); } catch (const Error&) { }
                }
                throw Error(Failure::local_failure, "Windows could not create the non-exportable CNG installation key.");
            }
        };
    }

    std::unique_ptr<IInstallationKeyProvider> makeWindowsCngInstallationKeyProvider() { return std::make_unique<CngProvider>(); }
}
#else
namespace syslocker::nightflyer
{
    std::unique_ptr<IInstallationKeyProvider> makeWindowsCngInstallationKeyProvider()
    {
        throw Error(Failure::configuration, "Windows CNG installation keys are unavailable on this platform; provide a platform key provider.");
    }
}
#endif
