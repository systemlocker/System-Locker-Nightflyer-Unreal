# Security policy

## Trust boundary

Nightflyer treats the machine running the game as untrusted. The client
accepts only Ed25519-signed leases, statuses, decisions, and key transitions,
verified against keys pinned in the application configuration before any
claim is read. Responses must bind to the per-request proof JTI, the
installation key's thumbprint, and the application's system ID; exact member
profiles and strict JSON parsing reject substituted or extended objects.

Installation keys are P-256 keys. On Windows they live in the CNG key stores
and are created non-exportable, preferring the TPM-backed Platform Crypto
Provider; persistent state is DPAPI-protected per user, atomically replaced,
and signed by that key. On macOS the keychain holds both state and keys. On
Linux, memory sessions use a software key and persistent sessions require
adapters backed by a real secret store; there is no plaintext fallback. All
security-relevant randomness (proof JTIs, P-256 nonces, key generation) comes
from the operating system CSPRNG.

Transport security is HTTPS with engine certificate validation, bounded
response bodies, and idempotent in-flight retries that resend the exact same
bytes. Signature verification uses the vendored Ed25519 and P-256
implementations compiled into the module — never the
engine, and never a system crypto library the module does not control.

## Accepted limitations

- A lease's offline grace period is real authority: a device that stays
  offline cannot be revoked until the signed expiry elapses. Choose
  `requestedOfflineSeconds` accordingly and call `tick()` while protected
  work runs.
- Software-only persistence cannot detect every coordinated rollback of both
  an old signed state snapshot and the OS clock. `requireOnlineAfterReboot`
  narrows this at the cost of requiring connectivity after each boot.
- The engine's HTTP layer follows redirects. The protocol pins HTTPS origins
  and no endpoint redirects, so a followed redirect would have to originate
  from the pinned host itself; treat this as an accepted engine behavior.
- HTTP behavior and platform services can vary with engine and project
  settings. Validate the flows you rely on in your own packaged build before
  shipping.
- Nightflyer raises the bar for casual piracy but is not tamper protection:
  a determined attacker with full control of the machine can patch the
  client. Combine it with engine-side hardening appropriate to your threat
  model.
