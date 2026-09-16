// Copyright (c) 2026 System Locker. All rights reserved.

#pragma once

// Unreal Engine HTTP adapter for the engine-independent Nightflyer client.

#include "syslocker/nightflyer.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace syslocker::nightflyer
{
    /// Creates an IHttpClient backed by Unreal Engine's HTTP module. Requests
    /// start on the game thread while the calling worker thread waits for the
    /// response. Calling it from the game thread fails instead of deadlocking.
    /// Certificate validation follows the engine's HTTP settings; response
    /// bodies above 1 MiB are rejected.
    SYSTEMLOCKERNIGHTFLYER_API std::shared_ptr<IHttpClient> makeUnrealHttpTransport(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(15000),
        std::string userAgent = "systemlocker-nightflyer-ue/0.2.0");
}
