// Copyright (c) 2026 System Locker. All rights reserved.

#pragma once

// Blueprint surface over the engine-free Nightflyer core. Sessions run their
// network work on background threads; results are broadcast on the game
// thread. C++ projects can use syslocker/nightflyer.hpp directly.

#include "CoreMinimal.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "NightflyerBlueprintLibrary.generated.h"

UENUM(BlueprintType)
enum class ENightflyerAuthorizationState : uint8
{
    AuthorizedOnline,
    AuthorizedOffline,
    RenewalDue,
    Expired,
    Ending,
    Ended,
    Inactive,
    AuthModeInUse,
    ProtocolUpgradeRequired,
    ClockUntrusted,
    DeviceChanged,
    AuthDenied,
    StorageUnavailable,
    NetworkUnavailable,
    ProtocolFailure,
    InstallationInUse,
};

UENUM(BlueprintType)
enum class ENightflyerRecommendedAction : uint8
{
    None,
    ContinueOffline,
    RetryOnline,
    RequestLicenseKey,
    UpdateClient,
    CheckClock,
    RepairProtectedStorage,
    ResolveDeviceBinding,
    ResolveAuthenticationMode,
    WaitForInstallation,
    ContactDeveloper,
};

/** Pinned trust roots and policies; fill from your project's configuration. */
USTRUCT(BlueprintType)
struct SYSTEMLOCKERNIGHTFLYER_API FNightflyerSettings
{
    GENERATED_BODY()

    /** 20-character system identifier from the dashboard. */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    FString SystemId;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    FString BaseUrl = TEXT("https://systemlocker.net");

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    FString ExpectedIssuer = TEXT("https://systemlocker.net");

    /** Signing key IDs to base64url Ed25519 keys. Never fill this from a server response. */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    TMap<FString, FString> TrustedSigningKeys;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    int32 RequestTimeoutSeconds = 15;

    /** 0-5 idempotent in-flight retries that resend the exact same bytes. */
    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    int32 IdempotentRetries = 1;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    bool RequireOnlineAfterReboot = false;
};

USTRUCT(BlueprintType)
struct SYSTEMLOCKERNIGHTFLYER_API FNightflyerBinding
{
    GENERATED_BODY()

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    FString Version;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    FString ProgramDigest;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Nightflyer")
    FString SlHwid;
};

USTRUCT(BlueprintType)
struct SYSTEMLOCKERNIGHTFLYER_API FNightflyerAuthorizationResult
{
    GENERATED_BODY()

    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    ENightflyerAuthorizationState State = ENightflyerAuthorizationState::AuthDenied;

    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    bool CanProceed = false;

    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    bool IsOffline = false;

    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    bool CredentialPresent = false;

    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    bool ShouldPromptForKey = false;

    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    ENightflyerRecommendedAction RecommendedAction = ENightflyerRecommendedAction::ContactDeveloper;

    /** Seconds until the suggested retry when state asks you to wait. */
    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    int32 RetryAfterSeconds = 0;

    /** Signed lease lifetime in UTC seconds, when authorized. */
    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    int64 LeaseExpiresAtUtc = 0;

    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    int64 LeaseRenewAfterUtc = 0;

    UPROPERTY(BlueprintReadOnly, Category = "Nightflyer")
    FString Diagnostic;
};

// A callback parameter is single-cast. Multicast delegates are Blueprint-
// assignable properties and are not accepted as UFUNCTION parameters by UHT.
DECLARE_DYNAMIC_DELEGATE_OneParam(FNightflyerAuthorizationDelegate, const FNightflyerAuthorizationResult&, Result);

UCLASS()
class SYSTEMLOCKERNIGHTFLYER_API UNightflyerBlueprintLibrary final : public UBlueprintFunctionLibrary
{
    GENERATED_BODY()

public:
    /**
     * Runs the recommended startup and recovery flow asynchronously and
     * invokes the callback on the game thread. Pass a license key on first
     * run (or to replace a denied one); pass an empty string to reuse the
     * retained credential. One session exists per system ID.
     */
    UFUNCTION(BlueprintCallable, Category = "Nightflyer", meta = (WorldContext = "WorldContextObject", AutoCreateRefTerm = "Settings,Binding"))
    static void EasyAuthorize(UObject* WorldContextObject, const FNightflyerSettings& Settings, const FNightflyerBinding& Binding, int32 RequestedOfflineSeconds, const FString& LicenseKey, bool Persistent, FNightflyerAuthorizationDelegate OnComplete);

    /** Runs one lease scheduler pass (renew when due) and invokes the callback. */
    UFUNCTION(BlueprintCallable, Category = "Nightflyer", meta = (WorldContext = "WorldContextObject", AutoCreateRefTerm = "Settings,Binding"))
    static void TickSession(UObject* WorldContextObject, const FNightflyerSettings& Settings, const FNightflyerBinding& Binding, FNightflyerAuthorizationDelegate OnComplete);

    /** Ends the active lease for the system (best effort; exact-retry safe). Invokes the callback with the final state. */
    UFUNCTION(BlueprintCallable, Category = "Nightflyer", meta = (WorldContext = "WorldContextObject", AutoCreateRefTerm = "Settings"))
    static void EndSession(UObject* WorldContextObject, const FNightflyerSettings& Settings, FNightflyerAuthorizationDelegate OnComplete);

    /** Asynchronously removes this system's terminal installation record. Active or pending leases are left intact. */
    UFUNCTION(BlueprintCallable, Category = "Nightflyer", meta = (WorldContext = "WorldContextObject", AutoCreateRefTerm = "Settings"))
    static void ForgetInstallation(UObject* WorldContextObject, const FNightflyerSettings& Settings);
};
