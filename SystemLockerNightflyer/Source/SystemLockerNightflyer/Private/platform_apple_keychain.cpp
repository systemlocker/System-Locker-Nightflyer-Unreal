// Copyright (c) 2026 System Locker. All rights reserved.

// macOS persistence adapters: keychain-backed state store and keychain-held
// P-256 installation keys. These compile only on Apple targets.

#include "internal.hpp"

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <array>
#include <vector>

namespace syslocker::nightflyer
{
    namespace
    {
        template<typename Released>
        class ScopedCF final
        {
        public:
            ScopedCF(Released value) : value_(value) {}
            ~ScopedCF() { if (value_) CFRelease(value_); }
            ScopedCF(const ScopedCF&) = delete;
            ScopedCF& operator=(const ScopedCF&) = delete;
            Released get() const { return value_; }
            Released release() { const auto value = value_; value_ = nullptr; return value; }
        private:
            Released value_ = nullptr;
        };

        CFStringRef makeString(const std::string& value)
        {
            const auto result = CFStringCreateWithCString(kCFAllocatorDefault, value.c_str(), kCFStringEncodingUTF8);
            if (!result) throw Error(Failure::local_failure, "A keychain string could not be created.");
            return result;
        }

        CFDataRef makeData(std::string_view value)
        {
            const auto result = CFDataCreate(
                kCFAllocatorDefault,
                reinterpret_cast<const UInt8*>(value.data()),
                static_cast<CFIndex>(value.size()));
            if (!result) throw Error(Failure::local_failure, "A keychain identifier could not be created.");
            return result;
        }

        /// Generic-password state item protected by the user's keychain.
        class KeychainStateStore final : public IStateStore
        {
        public:
            KeychainStateStore(std::string service, std::string account)
                : service_(std::move(service)), account_(std::move(account))
            {
                if (service_.empty() || account_.empty()) throw Error(Failure::configuration, "Keychain service and account names are required.");
            }

            std::optional<std::vector<unsigned char>> load() override
            {
                const ScopedCF<CFStringRef> service(makeString(service_));
                const ScopedCF<CFStringRef> account(makeString(account_));
                const ScopedCF<CFMutableDictionaryRef> query(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
                CFDictionaryAddValue(query.get(), kSecClass, kSecClassGenericPassword);
                CFDictionaryAddValue(query.get(), kSecAttrService, service.get());
                CFDictionaryAddValue(query.get(), kSecAttrAccount, account.get());
                CFDictionaryAddValue(query.get(), kSecReturnData, kCFBooleanTrue);
                CFTypeRef item = nullptr;
                const auto status = SecItemCopyMatching(query.get(), &item);
                if (status == errSecItemNotFound) return {};
                if (status != errSecSuccess) throw Error(Failure::local_failure, "The keychain could not be read.");
                const ScopedCF<CFDataRef> data(static_cast<CFDataRef>(item));
                const auto* bytes = CFDataGetBytePtr(data.get());
                return std::vector<unsigned char>(bytes, bytes + CFDataGetLength(data.get()));
            }

            void save(const std::vector<unsigned char>& value) override
            {
                if (value.empty() || value.size() > 2097152) throw Error(Failure::local_failure, "Nightflyer state has an invalid size.");
                const ScopedCF<CFStringRef> service(makeString(service_));
                const ScopedCF<CFStringRef> account(makeString(account_));
                const ScopedCF<CFDataRef> data(CFDataCreate(kCFAllocatorDefault, value.data(), static_cast<CFIndex>(value.size())));
                if (!data) throw Error(Failure::local_failure, "The keychain could not store Nightflyer state.");
                const ScopedCF<CFMutableDictionaryRef> attributes(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
                CFDictionaryAddValue(attributes.get(), kSecClass, kSecClassGenericPassword);
                CFDictionaryAddValue(attributes.get(), kSecAttrService, service.get());
                CFDictionaryAddValue(attributes.get(), kSecAttrAccount, account.get());
                const ScopedCF<CFMutableDictionaryRef> update(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
                CFDictionaryAddValue(update.get(), kSecValueData, data.get());
                // The state must survive reboots but nothing stronger than the
                // user's own keychain protection is claimed.
                CFDictionaryAddValue(update.get(), kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlock);
                auto status = SecItemUpdate(attributes.get(), update.get());
                if (status == errSecItemNotFound)
                {
                    const ScopedCF<CFMutableDictionaryRef> add(CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, attributes.get()));
                    CFDictionaryAddValue(add.get(), kSecValueData, data.get());
                    CFDictionaryAddValue(add.get(), kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlock);
                    status = SecItemAdd(add.get(), nullptr);
                }
                if (status != errSecSuccess) throw Error(Failure::local_failure, "The keychain could not store Nightflyer state.");
            }

            void erase() override
            {
                const ScopedCF<CFStringRef> service(makeString(service_));
                const ScopedCF<CFStringRef> account(makeString(account_));
                const ScopedCF<CFMutableDictionaryRef> query(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
                CFDictionaryAddValue(query.get(), kSecClass, kSecClassGenericPassword);
                CFDictionaryAddValue(query.get(), kSecAttrService, service.get());
                CFDictionaryAddValue(query.get(), kSecAttrAccount, account.get());
                const auto status = SecItemDelete(query.get());
                if (status != errSecSuccess && status != errSecItemNotFound) throw Error(Failure::local_failure, "The keychain could not remove Nightflyer state.");
            }

            std::string lockIdentity() const override { return "keychain:" + service_ + ":" + account_; }

        private:
            std::string service_;
            std::string account_;
        };

        class KeychainInstallationKey final : public InstallationKey::Impl
        {
        public:
            explicit KeychainInstallationKey(SecKeyRef key) : key_(key)
            {
                if (!key_) throw Error(Failure::local_failure, "The keychain installation key is unavailable.");
                const ScopedCF<SecKeyRef> publicKey(SecKeyCopyPublicKey(key_));
                if (!publicKey.get()) throw Error(Failure::local_failure, "Could not read the keychain installation public key.");
                CFErrorRef error = nullptr;
                const ScopedCF<CFDataRef> data(SecKeyCopyExternalRepresentation(publicKey.get(), &error));
                const ScopedCF<CFErrorRef> ownedError(error);
                if (!data.get())
                    throw Error(Failure::local_failure, "Could not read the keychain installation public key.");
                const auto* bytes = CFDataGetBytePtr(data.get());
                const auto length = static_cast<std::size_t>(CFDataGetLength(data.get()));
                // External representation of an EC key is the ANSI X9.63 point: 0x04 || x || y.
                if (length != 65 || bytes[0] != 0x04) throw Error(Failure::local_failure, "The keychain installation key is not P-256.");
                std::copy_n(bytes + 1, 64, coordinates_.begin());
            }

            ~KeychainInstallationKey() override { if (key_) CFRelease(key_); }

            std::array<unsigned char, 64> publicCoordinates() const override { return coordinates_; }

            std::array<unsigned char, 64> signSha256(std::string_view input) const override
            {
                const ScopedCF<CFDataRef> message(CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const unsigned char*>(input.data()), static_cast<CFIndex>(input.size())));
                if (!message) throw Error(Failure::local_failure, "Keychain installation signing failed.");
                const ScopedCF<CFDataRef> signature(SecKeyCreateSignature(key_, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, message.get(), nullptr));
                if (!signature) throw Error(Failure::local_failure, "Keychain installation signing failed.");
                const auto* bytes = CFDataGetBytePtr(signature.get());
                const auto* end = bytes + CFDataGetLength(signature.get());
                const auto raw = crypto::derToP1363(bytes, static_cast<std::size_t>(end - bytes));
                if (raw.size() != 64) throw Error(Failure::local_failure, "Keychain installation signature encoding is invalid.");
                std::array<unsigned char, 64> result{};
                std::copy_n(raw.data(), 64, result.begin());
                return result;
            }

            bool verifySha256(std::string_view input, const std::array<unsigned char, 64>& signature) const override
            {
                const ScopedCF<CFDataRef> message(CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const unsigned char*>(input.data()), static_cast<CFIndex>(input.size())));
                const auto der = crypto::p1363ToDer(signature.data());
                const ScopedCF<CFDataRef> encoded(CFDataCreate(kCFAllocatorDefault, der.data(), static_cast<CFIndex>(der.size())));
                if (!message || !encoded) throw Error(Failure::local_failure, "Keychain state verification failed.");
                const auto result = SecKeyVerifySignature(key_, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, message.get(), encoded.get(), nullptr);
                if (result) return true;
                // A malformed signature reports false on every platform rather
                // than an error distinction; treat both as verification failure.
                return false;
            }

            std::string exportPrivateKey() const override { throw Error(Failure::local_failure, "Keychain installation keys cannot be exported."); }

        private:
            SecKeyRef key_ = nullptr;
            std::array<unsigned char, 64> coordinates_{};
        };

        std::string tagName(const std::string& systemId, const std::string& suffix)
        {
            return "com.systemlocker.nightflyer." + systemId + "." + suffix;
        }

        std::pair<std::string, std::string> parseReference(const std::string& systemId, const std::string& reference)
        {
            static const std::string prefix = "keychain-v1:";
            if (reference.rfind(prefix, 0) != 0) throw Error(Failure::invalid_state, "The persistent keychain key reference is invalid.");
            const auto bytes = detail::unb64(reference.substr(prefix.size()), 0, Failure::invalid_state);
            const auto value = detail::strictJson(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()), Failure::invalid_state, "The persistent keychain key reference is invalid.");
            detail::exact(value, {"tag"}, "keychain key reference", Failure::invalid_state);
            const auto tag = detail::text(value, "tag", Failure::invalid_state);
            if (tag.rfind(tagName(systemId, ""), 0) != 0) throw Error(Failure::invalid_state, "The persistent keychain key belongs to another system.");
            return {tag, tag.substr(tagName(systemId, "").size())};
        }

            std::string referenceFor(const std::string& tag)
            {
                const auto encoded = detail::json{{"tag", tag}}.dump(-1, ' ', false, detail::json::error_handler_t::strict);
                return "keychain-v1:" + detail::b64(reinterpret_cast<const unsigned char*>(encoded.data()), encoded.size());
            }

        class KeychainProvider final : public IInstallationKeyProvider
        {
        public:
            InstallationKeyHandle create(std::string_view systemId) override
            {
                std::array<unsigned char, 8> random{};
                crypto::random(random.data(), random.size());
                return openOrCreate(tagName(std::string(systemId), detail::b64(random.data(), random.size())), true);
            }

            InstallationKeyHandle load(std::string_view systemId, std::string_view reference) override
            {
                const auto [tag, suffix] = parseReference(std::string(systemId), std::string(reference));
                ScopedCF<SecKeyRef> key(openByTag(tag));
                if (!key.get()) throw Error(Failure::invalid_state, "The persistent keychain installation key is unavailable.");
                return {std::string(reference), InstallationKey(std::make_unique<KeychainInstallationKey>(key.release()))};
            }

            InstallationKeyHandle openOrCreateStable(std::string_view systemId) override
            {
                return openOrCreate(tagName(std::string(systemId), "memory"), false);
            }

            void erase(std::string_view systemId, std::string_view reference) override
            {
                const auto [tag, suffix] = parseReference(std::string(systemId), std::string(reference));
                (void)suffix;
                const ScopedCF<CFDataRef> tagValue(makeData(tag));
                const ScopedCF<CFMutableDictionaryRef> query(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
                CFDictionaryAddValue(query.get(), kSecClass, kSecClassKey);
                CFDictionaryAddValue(query.get(), kSecAttrApplicationTag, tagValue.get());
                const auto status = SecItemDelete(query.get());
                if (status != errSecSuccess && status != errSecItemNotFound)
                    throw Error(Failure::local_failure, "The keychain installation key could not be deleted.");
            }

        private:
            static SecKeyRef openByTag(const std::string& tag)
            {
                const ScopedCF<CFDataRef> tagValue(makeData(tag));
                const ScopedCF<CFMutableDictionaryRef> query(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
                CFDictionaryAddValue(query.get(), kSecClass, kSecClassKey);
                CFDictionaryAddValue(query.get(), kSecAttrApplicationTag, tagValue.get());
                CFDictionaryAddValue(query.get(), kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
                CFDictionaryAddValue(query.get(), kSecReturnRef, kCFBooleanTrue);
                CFTypeRef item = nullptr;
                if (SecItemCopyMatching(query.get(), &item) != errSecSuccess || !item) return nullptr;
                return static_cast<SecKeyRef>(item);
            }

            static InstallationKeyHandle openOrCreate(const std::string& tag, bool mustCreate)
            {
                if (!mustCreate)
                {
                    if (ScopedCF<SecKeyRef> existing(openByTag(tag)); existing.get())
                        return {referenceFor(tag), InstallationKey(std::make_unique<KeychainInstallationKey>(existing.release()))};
                }
                const ScopedCF<CFDataRef> tagValue(makeData(tag));
                const ScopedCF<CFNumberRef> bits(CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &bitSize_));
                const ScopedCF<CFMutableDictionaryRef> privateAttributes(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
                CFDictionaryAddValue(privateAttributes.get(), kSecAttrIsPermanent, kCFBooleanTrue);
                CFDictionaryAddValue(privateAttributes.get(), kSecAttrApplicationTag, tagValue.get());
                const ScopedCF<CFMutableDictionaryRef> attributes(CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
                CFDictionaryAddValue(attributes.get(), kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
                CFDictionaryAddValue(attributes.get(), kSecAttrKeySizeInBits, bits.get());
                CFDictionaryAddValue(attributes.get(), kSecPrivateKeyAttrs, privateAttributes.get());
                CFErrorRef error = nullptr;
                const ScopedCF<SecKeyRef> created(SecKeyCreateRandomKey(attributes.get(), &error));
                const ScopedCF<CFErrorRef> ownedError(error);
                if (created.get()) return {referenceFor(tag), InstallationKey(std::make_unique<KeychainInstallationKey>(created.release()))};
                if (!mustCreate)
                {
                    // Another process may have won the creation race.
                    if (ScopedCF<SecKeyRef> existing(openByTag(tag)); existing.get())
                        return {referenceFor(tag), InstallationKey(std::make_unique<KeychainInstallationKey>(existing.release()))};
                }
                throw Error(Failure::local_failure, "macOS could not create the keychain installation key.");
            }

            inline static const SInt32 bitSize_ = 256;
        };
    }

    std::unique_ptr<IStateStore> makeMacosKeychainStateStore(std::string serviceName, std::string accountName)
    {
        return std::make_unique<KeychainStateStore>(std::move(serviceName), std::move(accountName));
    }

    std::unique_ptr<IInstallationKeyProvider> makeMacosKeychainInstallationKeyProvider()
    {
        return std::make_unique<KeychainProvider>();
    }
}
#else
namespace syslocker::nightflyer
{
    std::unique_ptr<IStateStore> makeMacosKeychainStateStore(std::string, std::string)
    {
        throw Error(Failure::configuration, "Keychain state storage is available only on macOS; provide an IStateStore adapter.");
    }

    std::unique_ptr<IInstallationKeyProvider> makeMacosKeychainInstallationKeyProvider()
    {
        throw Error(Failure::configuration, "Keychain installation keys are available only on macOS; provide an IInstallationKeyProvider adapter.");
    }
}
#endif
