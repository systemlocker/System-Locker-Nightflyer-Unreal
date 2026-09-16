// Copyright (c) 2026 System Locker. All rights reserved.

#pragma once

#include "syslocker/nightflyer.hpp"
#include "crypto.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <regex>
#include <set>
#include <string>
#include <vector>

namespace syslocker::nightflyer
{
    struct InstallationKey::Impl
    {
        virtual ~Impl() = default;
        virtual std::array<unsigned char, 64> publicCoordinates() const = 0;
        virtual std::array<unsigned char, 64> signSha256(std::string_view input) const = 0;
        virtual bool verifySha256(std::string_view input, const std::array<unsigned char, 64>& signature) const = 0;
        virtual std::string exportPrivateKey() const = 0;
    };

    namespace detail
    {
        using json = nlohmann::json;
        inline constexpr std::int64_t maximumUnixTimestamp = 253402300799LL;
        inline constexpr std::uint64_t maximumSafeInteger = 9007199254740991ULL;

        inline std::string b64(const unsigned char* data, std::size_t length) { return crypto::base64Url(data, length); }
        inline std::string b64(const std::vector<unsigned char>& value) { return crypto::base64Url(value.data(), value.size()); }

        inline std::vector<unsigned char> unb64(const std::string& input, std::size_t expected = 0, Failure failure = Failure::invalid_token)
        {
            // Strict canonical base64url: no padding, only the URL alphabet, and
            // the re-encoded form must reproduce the input byte for byte.
            if (input.empty() || input.find('=') != std::string::npos || !std::all_of(input.begin(), input.end(), [](unsigned char value) {
                    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '-' || value == '_';
                })) throw Error(failure, "Invalid base64url encoding.");
            std::vector<unsigned char> result;
            result.reserve((input.size() * 3) / 4 + 3);
            unsigned int group = 0;
            int groupBits = 0;
            for (const char character : input)
            {
                unsigned char value;
                if (character >= 'A' && character <= 'Z') value = static_cast<unsigned char>(character - 'A');
                else if (character >= 'a' && character <= 'z') value = static_cast<unsigned char>(character - 'a' + 26);
                else if (character >= '0' && character <= '9') value = static_cast<unsigned char>(character - '0' + 52);
                else if (character == '-') value = 62;
                else value = 63; // '_'
                group = (group << 6) | value;
                groupBits += 6;
                if (groupBits >= 8)
                {
                    groupBits -= 8;
                    result.push_back(static_cast<unsigned char>((group >> groupBits) & 0xff));
                }
            }
            if ((expected != 0 && result.size() != expected) || b64(result) != input) throw Error(failure, "Non-canonical base64url encoding.");
            return result;
        }

        inline std::string sha256(std::string_view input) { return crypto::sha256Base64Url(input); }

        inline bool fixedEqual(std::string_view left, std::string_view right) { return crypto::fixedTimeEqual(left, right); }

        inline bool isKid(const std::string& value)
        {
            static const std::regex pattern("^[0-9A-HJKMNP-TV-Z]{26}$");
            return std::regex_match(value, pattern);
        }

        inline bool isSystemId(const std::string& value)
        {
            return value.size() == 20 && std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isalnum(c) != 0; });
        }

        inline bool isUuidV4(const std::string& value)
        {
            static const std::regex pattern("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
            return std::regex_match(value, pattern);
        }

        inline std::string origin(const std::string& value, const char* name)
        {
            static const std::regex pattern("^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/?$");
            if (!std::regex_match(value, pattern)) throw Error(Failure::configuration, std::string(name) + " must be a lowercase HTTPS origin without a path, query, fragment, or credentials.");
            return !value.empty() && value.back() == '/' ? value.substr(0, value.size() - 1) : value;
        }

        inline json strictJson(std::string_view input, Failure failure, std::string message)
        {
            bool duplicate = false;
            std::vector<std::set<std::string>> objects;
            auto callback = [&objects, &duplicate](int, json::parse_event_t event, json& parsed) {
                if (event == json::parse_event_t::object_start) objects.emplace_back();
                else if (event == json::parse_event_t::key)
                {
                    if (objects.empty() || !objects.back().insert(parsed.get<std::string>()).second) duplicate = true;
                }
                else if (event == json::parse_event_t::object_end)
                {
                    if (objects.empty()) duplicate = true;
                    else objects.pop_back();
                }
                return true;
            };
            try
            {
                auto parsed = json::parse(input, callback, true, false);
                if (duplicate || !objects.empty()) throw Error(failure, "Duplicate JSON member.");
                return parsed;
            }
            catch (const Error&) { throw; }
            catch (const json::exception&) { throw Error(failure, std::move(message)); }
        }

        inline void exact(const json& value, const std::vector<std::string>& fields, std::string_view name, Failure failure = Failure::invalid_token)
        {
            if (!value.is_object()) throw Error(failure, std::string(name) + " must be an object.");
            std::set<std::string> actual;
            for (auto iterator = value.begin(); iterator != value.end(); ++iterator) actual.insert(iterator.key());
            const std::set<std::string> expected(fields.begin(), fields.end());
            if (actual != expected) throw Error(failure, std::string(name) + " has an unexpected member profile.");
        }

        inline std::string text(const json& object, const char* name, Failure failure = Failure::invalid_token)
        {
            const auto iterator = object.find(name);
            if (iterator == object.end() || !iterator->is_string()) throw Error(failure, std::string(name) + " must be a string.");
            return iterator->get<std::string>();
        }

        inline std::int64_t integer(const json& object, const char* name, Failure failure = Failure::invalid_token)
        {
            const auto iterator = object.find(name);
            if (iterator == object.end() || !iterator->is_number_integer()) throw Error(failure, std::string(name) + " must be an integer.");
            try { return iterator->get<std::int64_t>(); }
            catch (const json::exception&) { throw Error(failure, std::string(name) + " is outside the supported integer range."); }
        }

        inline std::uint64_t safeNonnegative(const json& object, const char* name)
        {
            const auto value = integer(object, name);
            if (value < 0 || static_cast<std::uint64_t>(value) > maximumSafeInteger) throw Error(Failure::invalid_token, std::string(name) + " is outside the supported integer range.");
            return static_cast<std::uint64_t>(value);
        }

        inline std::uint64_t safePositive(const json& object, const char* name)
        {
            const auto value = safeNonnegative(object, name);
            if (value == 0) throw Error(Failure::invalid_token, std::string(name) + " must be positive.");
            return value;
        }

        inline std::int64_t timestamp(const json& object, const char* name)
        {
            const auto value = integer(object, name);
            if (value < 0 || value > maximumUnixTimestamp) throw Error(Failure::invalid_token, std::string(name) + " is outside the supported timestamp range.");
            return value;
        }

        inline std::vector<std::string> compactParts(const std::string& compact)
        {
            if (compact.empty() || !std::all_of(compact.begin(), compact.end(), [](unsigned char c) { return c <= 0x7f; })) throw Error(Failure::invalid_token, "Invalid compact JWS.");
            std::vector<std::string> result;
            std::size_t start = 0;
            for (;;)
            {
                const auto end = compact.find('.', start);
                result.push_back(compact.substr(start, end == std::string::npos ? end : end - start));
                if (end == std::string::npos) break;
                start = end + 1;
            }
            if (result.size() != 3 || std::any_of(result.begin(), result.end(), [](const auto& part) { return part.empty(); })) throw Error(Failure::invalid_token, "Invalid compact JWS.");
            return result;
        }
    }
}
