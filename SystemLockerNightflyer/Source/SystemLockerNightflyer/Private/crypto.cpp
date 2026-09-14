#include "crypto.hpp"

#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__APPLE__)
#include <stdlib.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace syslocker::nightflyer::crypto
{
    namespace
    {
        struct Sha256Schedule
        {
            static constexpr std::array<unsigned int, 64> roundConstants{
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
            };

            unsigned int state[8]{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
            unsigned long long bitCount = 0;
            unsigned char buffer[64]{};
            std::size_t buffered = 0;

            static unsigned int rotateRight(unsigned int value, unsigned int count) { return (value >> count) | (value << (32 - count)); }

            void transform(const unsigned char* block)
            {
                unsigned int w[64];
                for (int index = 0; index < 16; ++index)
                {
                    w[index] = (static_cast<unsigned int>(block[index * 4]) << 24) | (static_cast<unsigned int>(block[index * 4 + 1]) << 16)
                        | (static_cast<unsigned int>(block[index * 4 + 2]) << 8) | static_cast<unsigned int>(block[index * 4 + 3]);
                }
                for (int index = 16; index < 64; ++index)
                {
                    const unsigned int s0 = rotateRight(w[index - 15], 7) ^ rotateRight(w[index - 15], 18) ^ (w[index - 15] >> 3);
                    const unsigned int s1 = rotateRight(w[index - 2], 17) ^ rotateRight(w[index - 2], 19) ^ (w[index - 2] >> 10);
                    w[index] = w[index - 16] + s0 + w[index - 7] + s1;
                }
                unsigned int a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
                for (int index = 0; index < 64; ++index)
                {
                    const unsigned int sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
                    const unsigned int choice = (e & f) ^ (~e & g);
                    const unsigned int temp1 = h + sum1 + choice + roundConstants[index] + w[index];
                    const unsigned int sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
                    const unsigned int majority = (a & b) ^ (a & c) ^ (b & c);
                    const unsigned int temp2 = sum0 + majority;
                    h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
                }
                state[0] += a; state[1] += b; state[2] += c; state[3] += d;
                state[4] += e; state[5] += f; state[6] += g; state[7] += h;
            }

            void update(const unsigned char* data, std::size_t length)
            {
                bitCount += static_cast<unsigned long long>(length) * 8;
                while (length > 0)
                {
                    const auto take = std::min(length, sizeof(buffer) - buffered);
                    std::memcpy(buffer + buffered, data, take);
                    buffered += take; data += take; length -= take;
                    if (buffered == sizeof(buffer)) { transform(buffer); buffered = 0; }
                }
            }

            std::array<unsigned char, 32> finish()
            {
                const auto bits = bitCount;
                unsigned char padding = 0x80;
                update(&padding, 1);
                padding = 0;
                while (buffered != 56) update(&padding, 1);
                unsigned char lengthBytes[8];
                for (int index = 0; index < 8; ++index) lengthBytes[index] = static_cast<unsigned char>(bits >> (56 - index * 8));
                // Direct write: appending length bytes must not recount bits.
                std::memcpy(buffer + 56, lengthBytes, 8);
                transform(buffer);
                buffered = 0;
                std::array<unsigned char, 32> digest{};
                for (int index = 0; index < 8; ++index)
                {
                    digest[index * 4] = static_cast<unsigned char>(state[index] >> 24);
                    digest[index * 4 + 1] = static_cast<unsigned char>(state[index] >> 16);
                    digest[index * 4 + 2] = static_cast<unsigned char>(state[index] >> 8);
                    digest[index * 4 + 3] = static_cast<unsigned char>(state[index]);
                }
                return digest;
            }
        };

        const char* encodingAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        unsigned char decodingValue(char value)
        {
            if (value >= 'A' && value <= 'Z') return static_cast<unsigned char>(value - 'A');
            if (value >= 'a' && value <= 'z') return static_cast<unsigned char>(value - 'a' + 26);
            if (value >= '0' && value <= '9') return static_cast<unsigned char>(value - '0' + 52);
            if (value == '-') return 62;
            if (value == '_') return 63;
            return 0xff;
        }
    }

    std::array<unsigned char, 32> sha256(std::string_view input)
    {
        Sha256Schedule schedule;
        schedule.update(reinterpret_cast<const unsigned char*>(input.data()), input.size());
        return schedule.finish();
    }

    std::string sha256Base64Url(std::string_view input)
    {
        const auto digest = sha256(input);
        return base64Url(digest.data(), digest.size());
    }

    bool fixedTimeEqual(const unsigned char* left, const unsigned char* right, std::size_t length)
    {
        unsigned char difference = 0;
        for (std::size_t index = 0; index < length; ++index) difference |= static_cast<unsigned char>(left[index] ^ right[index]);
        return difference == 0;
    }

    bool fixedTimeEqual(std::string_view left, std::string_view right)
    {
        return left.size() == right.size() && fixedTimeEqual(reinterpret_cast<const unsigned char*>(left.data()), reinterpret_cast<const unsigned char*>(right.data()), left.size());
    }

    std::string base64Url(const unsigned char* data, std::size_t length)
    {
        std::string result;
        result.reserve(4 * ((length + 2) / 3));
        std::size_t position = 0;
        while (position + 3 <= length)
        {
            const unsigned triple = (static_cast<unsigned>(data[position]) << 16) | (static_cast<unsigned>(data[position + 1]) << 8) | static_cast<unsigned>(data[position + 2]);
            result.push_back(encodingAlphabet[(triple >> 18) & 63]);
            result.push_back(encodingAlphabet[(triple >> 12) & 63]);
            result.push_back(encodingAlphabet[(triple >> 6) & 63]);
            result.push_back(encodingAlphabet[triple & 63]);
            position += 3;
        }
        const auto remaining = length - position;
        if (remaining == 1)
        {
            const auto pair = static_cast<unsigned>(data[position]) << 16;
            result.push_back(encodingAlphabet[(pair >> 18) & 63]);
            result.push_back(encodingAlphabet[(pair >> 12) & 63]);
        }
        else if (remaining == 2)
        {
            const auto pair = (static_cast<unsigned>(data[position]) << 16) | (static_cast<unsigned>(data[position + 1]) << 8);
            result.push_back(encodingAlphabet[(pair >> 18) & 63]);
            result.push_back(encodingAlphabet[(pair >> 12) & 63]);
            result.push_back(encodingAlphabet[(pair >> 6) & 63]);
        }
        return result;
    }

    void random(unsigned char* data, std::size_t length)
    {
        while (length > 0)
        {
#ifdef _WIN32
            // The system-preferred RNG resolves to the platform PRNG (TPM-backed
            // where available) with no provider handle to manage.
            const auto take = static_cast<unsigned long>(std::min<std::size_t>(length, 4096));
            if (BCryptGenRandom(nullptr, data, take, 0x00000002 /* BCRYPT_USE_SYSTEM_PREFERRED_RNG */) != 0)
                throw std::runtime_error("The system CSPRNG is unavailable.");
            data += take; length -= take;
#elif defined(__APPLE__)
            // arc4random_buf has no error return and aborts rather than emit
            // weak output if the operating-system generator is unavailable.
            arc4random_buf(data, length);
            length = 0;
#else
            const int descriptor = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
            if (descriptor < 0) throw std::runtime_error("The system CSPRNG is unavailable.");
            std::size_t filled = 0;
            while (filled < length)
            {
                const auto taken = ::read(descriptor, data + filled, length - filled);
                if (taken <= 0) { ::close(descriptor); throw std::runtime_error("The system CSPRNG is unavailable."); }
                filled += static_cast<std::size_t>(taken);
            }
            ::close(descriptor);
            length = 0;
#endif
        }
    }

    std::vector<unsigned char> derToP1363(const unsigned char* der, std::size_t length)
    {
        auto readLength = [&der, &length](std::size_t& position) -> std::size_t
        {
            if (position >= length) throw std::invalid_argument("length");
            const auto first = der[position++];
            if (first < 0x80) return first;
            const auto count = first & 0x7f;
            if (count == 0 || count > 4 || position + count > length) throw std::invalid_argument("length");
            std::size_t value = 0;
            for (std::size_t index = 0; index < count; ++index) value = (value << 8) | der[position++];
            return value;
        };
        auto readInteger = [&der, &length, &readLength](std::size_t& position) -> std::vector<unsigned char>
        {
            if (position >= length || der[position++] != 0x02) throw std::invalid_argument("integer");
            const auto size = readLength(position);
            if (size == 0 || size > 33 || position + size > length) throw std::invalid_argument("integer");
            auto value = std::vector<unsigned char>(der + position, der + position + size);
            position += size;
            if (size == 33) { if (value[0] != 0) throw std::invalid_argument("integer"); value.erase(value.begin()); }
            else if (value.empty() || value[0] == 0) throw std::invalid_argument("integer"); // non-minimal
            return value;
        };
        try
        {
            std::size_t position = 0;
            if (position >= length || der[position++] != 0x30) return {};
            const auto body = readLength(position);
            if (position + body != length) return {};
            const auto r = readInteger(position);
            const auto s = readInteger(position);
            if (position != length || r.size() > 32 || s.size() > 32) return {};
            std::vector<unsigned char> result(64, 0);
            std::memcpy(result.data() + (32 - r.size()), r.data(), r.size());
            std::memcpy(result.data() + (64 - s.size()), s.data(), s.size());
            return result;
        }
        catch (const std::invalid_argument&) { return {}; }
    }

    std::vector<unsigned char> p1363ToDer(const unsigned char* signature)
    {
        auto trim = [](const unsigned char* value) -> std::pair<std::size_t, std::size_t>
        {
            std::size_t start = 0;
            while (start < 31 && value[start] == 0) ++start;
            return {start, 32 - start};
        };
        auto writeInteger = [](std::vector<unsigned char>& out, const unsigned char* value, std::size_t offset, std::size_t size)
        {
            out.push_back(0x02);
            const bool highBit = value[offset] >= 0x80;
            out.push_back(static_cast<unsigned char>(size + (highBit ? 1 : 0)));
            if (highBit) out.push_back(0);
            out.insert(out.end(), value + offset, value + offset + size);
        };
        const auto [rOffset, rSize] = trim(signature);
        const auto [sOffset, sSize] = trim(signature + 32);
        // DER INTEGERs are signed: magnitudes with the high bit set need a leading zero.
        const auto rLength = rSize + (signature[rOffset] >= 0x80 ? 1 : 0);
        const auto sLength = sSize + (signature[sOffset + 32] >= 0x80 ? 1 : 0);
        const std::size_t body = 2 + rLength + 2 + sLength;
        std::vector<unsigned char> out;
        out.reserve(2 + body);
        out.push_back(0x30);
        out.push_back(static_cast<unsigned char>(body));
        writeInteger(out, signature, rOffset, rSize);
        writeInteger(out, signature + 32, sOffset, sSize);
        return out;
    }
}
