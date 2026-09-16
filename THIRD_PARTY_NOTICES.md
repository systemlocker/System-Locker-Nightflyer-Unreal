# Third-party notices

This plugin vendors three permissive third-party components so it builds with
no external dependencies. Provenance, pinned versions, and licenses for each
live alongside the code under `Source/ThirdParty/`;
the sections below summarize what ships and under which terms.

## orlp/ed25519 (verify-only subset)

Ed25519 signature verification derived from the reference implementation.
Vendored from https://github.com/orlp/ed25519 (master @ b1f19fa, 2022-10-02);
only the files needed for verification are included. Zlib license — see
`Source/ThirdParty/ed25519/LICENSE.txt`. The module adds strict point, torsion,
and scalar canonicality checks around the vendored verifier before it trusts a
signature.

## micro-ecc (uECC)

Portable P-256 (secp256r1) arithmetic, signing, and verification by Kenneth
MacKay. Vendored from https://github.com/kmackay/micro-ecc (master). BSD
2-clause license — see `Source/ThirdParty/micro-ecc/LICENSE.txt`. Used for installation
keys on every platform and for persistent state signatures outside Windows.

## nlohmann/json

Single-header JSON parsing and serialization by Niels Lohmann. Vendored from
https://github.com/nlohmann/json (v3.11.3 release header). MIT license — see
`Source/ThirdParty/nlohmann/LICENSE.MIT`. Used with strict parsing settings (duplicate
members rejected, exact object profiles enforced by the caller).

No other third-party code is compiled into this plugin. The remaining
sources, including the SHA-256, base64url, DER conversion, and constant-time
comparison primitives, are original System Locker code.
