# Vendored dependencies

These components are bundled so the plugin builds without a separate package
manager. The source files include publisher distribution notices; upstream
copyrights and license terms remain with their respective authors. The full
license texts are included in each component's folder.

| Folder | Upstream | Version / commit | License | Used for |
| ------ | -------- | ---------------- | ------- | -------- |
| `ed25519/` | https://github.com/orlp/ed25519 (src/) | master @ b1f19fa (2022-10-02), verify-only subset | Zlib (see LICENSE.txt) | Ed25519 verification of server-signed leases, statuses, decisions, and key transitions |
| `micro-ecc/` | https://github.com/kmackay/micro-ecc | master (uECC v2.x) | BSD 2-clause (see LICENSE.txt) | Portable P-256 installation keys for memory sessions and non-Windows builds |
| `nlohmann/` | https://github.com/nlohmann/json single header | v3.11.3 | MIT (see LICENSE.MIT) | Strict JSON parsing and canonical serialization |

## Verify-only subset of orlp/ed25519

Only the files needed for `ed25519_verify` are vendored: `verify.c`, `ge.c`,
`fe.c`, `sc.c`, `sha512.c`, and their headers. Signing, key exchange, and
precomputation tooling are deliberately excluded; this client never signs with
Ed25519. The module adds its own strictness wrapper around `ed25519_verify`
(rejection of non-canonical points, small-order/torsion encodings, and
non-canonical scalars) before any signature is trusted.
