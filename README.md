# System Locker Nightflyer — Unreal Engine

Official Unreal Engine 5.3+ plugin for System Locker Nightflyer, an offline
authorization lease protocol for desktop software. Nightflyer proves
possession of an installation P-256 key on every request and accepts only
Ed25519-signed leases, statuses, decisions, and key transitions from locally
pinned keys.

Nightflyer requires a System Locker account and a configured Nightflyer system.
Initial authorization and periodic server checks need an internet connection;
a valid cached lease can authorize offline play until its signed expiry. Any
System Locker service charges are separate from this plugin.

The plugin is self-contained: Ed25519 verification, P-256 installation keys,
strict JSON, SHA-256, and base64url are compiled into the module. It links no
crypto library, package manager, or engine marketplace dependency.

## Install

Copy (or symlink) the `SystemLockerNightflyer` folder into your project's
`Plugins/` directory and regenerate project files. A Fab listing is planned;
add its product URL here after approval. C++ projects get the full native API;
Blueprint projects use the `UNightflyerBlueprintLibrary` nodes.

## Quickstart (C++)

```cpp
#include "Async/Async.h"
#include "syslocker/nightflyer.hpp"
#include "UnrealHttpTransport.h"

using namespace syslocker::nightflyer;

Config config;
config.systemId = "abcdefghijklmnopqrst";
config.trustedSigningKeys["YOUR_KID"] = "YOUR_BASE64URL_ED25519_KEY";

// Make NightflyerSession a long-lived member of your GameInstance. Disposing a
// memory session ends its lease.
NightflyerSession = std::make_shared<AuthorizationSession>(
    AuthorizationSession::memory(config, makeUnrealHttpTransport()));

auto session = NightflyerSession;
Async(EAsyncExecution::ThreadPool, [session, myHwid, enteredKey]()
{
    auto result = session->easyAuthorize({"1.0.0", "", myHwid}, 86400, enteredKey);
    AsyncTask(ENamedThreads::GameThread, [result = std::move(result)]()
    {
        if (result.canProceed)              StartProtectedWork();
        else if (result.shouldPromptForKey) ShowLicenseKeyPrompt();
    });
});
```

Keep calling `tick()` from a worker thread while protected game code is
active so due leases renew. During an orderly shutdown, call `end()` from a
worker thread before releasing the long-lived session.

For a persistent session on Windows:

```cpp
const auto path = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("Nightflyer.bin"));
NightflyerSession = std::make_shared<AuthorizationSession>(
    AuthorizationSession::persistent(
        config,
        makeWindowsDpapiStateStore(TCHAR_TO_UTF8(*path)),
        makeUnrealHttpTransport()));
```

## Quickstart (Blueprint)

Fill an `FNightflyerSettings` struct (system ID and pinned signing keys) and
call **Nightflyer Easy Authorize**; bind the completion delegate. The result
struct gives you `CanProceed`, `ShouldPromptForKey`, `IsOffline`,
`RecommendedAction`, and `LeaseExpiresAtUtc`. Sessions run on background
threads and results broadcast on the game thread. One session exists per
system ID; `Persistent = true` uses DPAPI + CNG on Windows and Keychain on
macOS. Linux Blueprint projects use memory mode unless C++ supplies protected
storage adapters. Call **Nightflyer Tick Session** periodically while protected
play is active, and **Nightflyer End Session** during orderly shutdown.

## Persistence by platform

- **Windows**: DPAPI-protected state store and non-exportable CNG installation
  keys (Platform Crypto Provider when the device has one) work out of the box.
- **macOS**: keychain state store and keychain-held installation keys are
  included (`makeMacosKeychainStateStore`, `makeMacosKeychainInstallationKeyProvider`).
- **Linux**: memory-only sessions work everywhere; persistent sessions need an
  `IStateStore`/`IInstallationKeyProvider` pair backed by a platform or
  application secret store — the plugin deliberately has no plaintext fallback.

The retained license key lets an inactive installation request a fresh lease
without asking the user again. Nightflyer erases it only after a signed
`KEY_NOT_FOUND` decision.

## EasyAuthorize and persistent startup

`easyAuthorize()` is the recommended startup API. With a newly entered key it
requests a fresh lease. Without one, it loads protected state, renews a due
lease or runs a strict status check, finishes any exact pending end request,
and requests a new lease with the retained key when the old lease is
inactive, ended, or expired.

The result makes application policy explicit: `canProceed`, `isOffline`,
`credentialPresent`, `shouldPromptForKey`, `retryAfter`, and a typed
`recommendedAction`. A `network_unavailable` result with `canProceed == true`
means the online check did not finish but the existing signed offline lease
is still usable.

If a developer **unbinds** a lease, it is reported as revoked and surfaces
locally as `inactive`; this is not a permanent ban on the installation or
key. `easyAuthorize()` immediately tries to obtain a new lease with the
retained key.

## What the client enforces

- HTTPS-only endpoints, refused redirects, and a fresh ES256 installation proof.
- Canonical request binding and access-token binding for renewal, status, and end.
- Ed25519 verification before token claims are consumed, with fixed JWS types
  and strict point/encoding checks (small-order and non-canonical values are
  rejected).
- Exact lease, status, and transition profiles; a status or decision cannot be
  substituted for a lease.
- Request-JTI, system, installation-thumbprint, expiry, and key-transition checks.
- Installation-key-signed state, replayable server-signed key transitions,
  persisted high-water marks, revocation enforcement, and per-boot time checks.
- A renewal state machine with cross-process installation coordination,
  terminal end tombstones, and offline-on-network-failure behavior.

## Offline time and travel

A valid cached lease can be used without connectivity, including while
traveling. During the same OS boot, lease time advances from verified server
UTC using an elapsed-time clock that includes sleep. Time-zone changes and
wall-clock corrections do not shorten or extend the signed lease lifetime.

After a reboot, a persisted lease remains usable by default when UTC is
consistent with the installation-key-signed high-water checkpoint. Set
`requireOnlineAfterReboot = true` for the stricter policy of requiring one
signed online response after every boot. Software-only storage cannot detect
every coordinated rollback of both an old signed state snapshot and the OS
clock. A successful signed online response repairs a bad local time
checkpoint but does not extend an existing lease's signed expiry. Memory-only
sessions are not persisted across application or OS restarts.

## Engine notes

- `makeUnrealHttpTransport()` must be used from a non-game thread (the
  Blueprint library already does this). Certificate validation follows the
  engine's HTTP settings and response bodies above 1 MiB are refused.
- The engine-free core (`Private/nightflyer.cpp`, `Private/authorization_session.cpp`,
  and the vendored code under `Source/ThirdParty/`) uses the same Nightflyer
  behavior as the standalone C++ client. See THIRD_PARTY_NOTICES.md for the
  bundled components and their licenses.

## Security addendum

> [!WARNING]
> Watch this repository and update the plugin when a release ships:
> releases regularly add security enhancements.

Pinned server keys are a developer-provided trust root. The session persists
the signed transition chain rather than a derived key-ring snapshot, then
replays it from those roots on every open. The session rejects revoked keys,
devices, grants, rollback, and stale leases. It uses the signed server-time
anchor plus a suspend-aware monotonic clock within a boot. Nightflyer cannot
immediately revoke a device that is offline, and even though it increases
resilience to cracking, it is not a substitute for proper obfuscation and
other protections. See SECURITY.md for the trust boundary and engine-specific
limitations.
