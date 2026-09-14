// Reference sample for README-style startup gating. This file is not
// compiled into the plugin; drop it into your game module and adapt it.

#include "Async/Async.h"
#include "UnrealHttpTransport.h"
#include "syslocker/nightflyer.hpp"

#include "HAL/PlatformFileManager.h"
#include "Misc/Paths.h"

namespace
{
    // In a real game, keep this on your GameInstance (or another object whose
    // lifetime covers all protected play).
    std::shared_ptr<syslocker::nightflyer::AuthorizationSession> ActiveSession;

    void GateGameStart(bool persistent, std::optional<std::string> licenseKey)
    {
        using namespace syslocker::nightflyer;

        Config config;
        config.systemId = "abcdefghijklmnopqrst";
        config.trustedSigningKeys["YOUR_KID"] = "YOUR_BASE64URL_ED25519_KEY";

        const std::string hwid = "your-hardware-id"; // e.g. FPlatformMisc::GetMachineId()
        // GateGameStart is called on the game thread, so copying the current
        // session here is safe. Reuse it when a player submits a key after the
        // initial prompt; creating a second memory session would contend with
        // the first installation lock.
        auto existingSession = ActiveSession;

        Async(EAsyncExecution::ThreadPool, [config = std::move(config), hwid, persistent, licenseKey = std::move(licenseKey), session = std::move(existingSession)]() mutable
        {
            try
            {
                if (!session)
                {
                    auto transport = makeUnrealHttpTransport();
                    if (persistent)
                    {
#if PLATFORM_WINDOWS
                        const auto directory = FPaths::Combine(FPaths::ProjectSavedDir(), TEXT("SystemLockerNightflyer"));
                        if (!IPlatformFile::GetPlatformPhysical().CreateDirectoryTree(*directory))
                            throw Error(Failure::local_failure, "The Nightflyer state directory could not be created.");
                        const auto path = FPaths::Combine(directory, TEXT("license.bin"));
                        session = std::make_shared<AuthorizationSession>(AuthorizationSession::persistent(
                            config,
                            makeWindowsDpapiStateStore(TCHAR_TO_UTF8(*path)),
                            transport));
#elif PLATFORM_MAC
                        session = std::make_shared<AuthorizationSession>(AuthorizationSession::persistent(
                            config,
                            makeMacosKeychainStateStore("com.systemlocker.nightflyer", config.systemId),
                            makeMacosKeychainInstallationKeyProvider(),
                            transport));
#else
                        throw Error(Failure::configuration, "Persistent Nightflyer storage needs a Linux C++ adapter.");
#endif
                    }
                    else
                    {
                        session = std::make_shared<AuthorizationSession>(AuthorizationSession::memory(config, transport));
                    }
                }

                auto result = session->easyAuthorize({"1.0.0", "", hwid}, 86400, std::move(licenseKey));
                AsyncTask(ENamedThreads::GameThread, [session = std::move(session), result = std::move(result)]() mutable
                {
                    ActiveSession = std::move(session);
                    if (result.canProceed)
                    {
                        UE_LOG(LogTemp, Display, TEXT("Nightflyer authorized until %lld."), static_cast<long long>(result.snapshot.lease->expiresAt));
                    }
                    else if (result.shouldPromptForKey)
                    {
                        UE_LOG(LogTemp, Warning, TEXT("Nightflyer needs a license key."));
                    }
                });
            }
            catch (const std::exception& error)
            {
                const FString diagnostic = UTF8_TO_TCHAR(error.what());
                AsyncTask(ENamedThreads::GameThread, [diagnostic]()
                {
                    UE_LOG(LogTemp, Error, TEXT("Nightflyer startup failed: %s"), *diagnostic);
                });
            }
        });
    }
}
