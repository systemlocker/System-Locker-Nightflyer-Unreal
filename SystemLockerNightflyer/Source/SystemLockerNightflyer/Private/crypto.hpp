#pragma once

// In-house cryptographic primitives for the engine-free Nightflyer core.
// The module intentionally does not link OpenSSL or any other crypto library:
// these few, small, auditable implementations plus the vendored Ed25519 and
// P-256 code under Vendor/ are the whole crypto surface.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace syslocker::nightflyer::crypto
{
    /// SHA-256 of the input, returned base64url-encoded without padding.
    std::string sha256Base64Url(std::string_view input);
    /// Raw 32-byte SHA-256 digest.
    std::array<unsigned char, 32> sha256(std::string_view input);

    /// Constant-time equality of equal-length byte ranges.
    bool fixedTimeEqual(const unsigned char* left, const unsigned char* right, std::size_t length);
    /// Constant-time string equality (input sizes leak; contents do not).
    bool fixedTimeEqual(std::string_view left, std::string_view right);

    /// Canonical base64url encoding (no padding).
    std::string base64Url(const unsigned char* data, std::size_t length);

    /// Fills the buffer from the operating system's CSPRNG; throws on failure.
    void random(unsigned char* data, std::size_t length);

    /// Converts an ASN.1 DER ECDSA signature to the fixed 64-byte r||s form.
    /// Returns an empty vector when the encoding is not a minimal ECDSA value.
    std::vector<unsigned char> derToP1363(const unsigned char* der, std::size_t length);

    /// Converts a 64-byte r||s signature to canonical ASN.1 DER.
    std::vector<unsigned char> p1363ToDer(const unsigned char* signature);
}
