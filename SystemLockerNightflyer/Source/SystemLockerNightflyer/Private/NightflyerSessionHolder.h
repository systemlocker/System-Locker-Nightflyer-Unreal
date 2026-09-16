// Copyright (c) 2026 System Locker. All rights reserved.

#pragma once

// Root'ed owner of native Nightflyer sessions so Blueprint-facing background
// tasks always have something valid to talk to.

#include "CoreMinimal.h"
#include "syslocker/nightflyer.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <string>

#include "NightflyerSessionHolder.generated.h"

struct FNightflyerSessionSlot final
{
    std::optional<syslocker::nightflyer::AuthorizationSession> Session;
    std::map<std::string, std::string> ActiveKeys;
    std::string BaseUrl;
    std::string ExpectedIssuer;
    std::chrono::milliseconds Timeout{0};
    int IdempotentRetries = 0;
    bool RequireOnlineAfterReboot = false;
    bool Persistent = false;

    bool Matches(const syslocker::nightflyer::Config& Config, bool IsPersistent) const
    {
        return Session.has_value()
            && ActiveKeys == Config.trustedSigningKeys
            && BaseUrl == Config.baseUrl
            && ExpectedIssuer == Config.expectedIssuer
            && Timeout == Config.timeout
            && IdempotentRetries == Config.idempotentTransportRetries
            && RequireOnlineAfterReboot == Config.requireOnlineAfterReboot
            && Persistent == IsPersistent;
    }

    void Remember(const syslocker::nightflyer::Config& Config, bool IsPersistent)
    {
        ActiveKeys = Config.trustedSigningKeys;
        BaseUrl = Config.baseUrl;
        ExpectedIssuer = Config.expectedIssuer;
        Timeout = Config.timeout;
        IdempotentRetries = Config.idempotentTransportRetries;
        RequireOnlineAfterReboot = Config.requireOnlineAfterReboot;
        Persistent = IsPersistent;
    }
};

UCLASS(MinimalAPI)
class UNightflyerSessionHolder final : public UObject
{
    GENERATED_BODY()

public:
    // Serializes every access to Sessions; Nightflyer sessions are not
    // internally thread-safe per instance.
    std::mutex Gate;
    std::map<std::string, FNightflyerSessionSlot> Sessions;

    static UNightflyerSessionHolder* Acquire()
    {
        static UNightflyerSessionHolder* Holder = [] {
            UNightflyerSessionHolder* Created = NewObject<UNightflyerSessionHolder>();
            // Never garbage collected; the process owns exactly one.
            Created->AddToRoot();
            return Created;
        }();
        return Holder;
    }
};
