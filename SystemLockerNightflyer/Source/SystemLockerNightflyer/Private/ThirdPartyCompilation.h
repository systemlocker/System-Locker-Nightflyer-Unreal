// Copyright (c) 2026 System Locker. All rights reserved.

#pragma once

#include <cstdint>

// orlp/ed25519's legacy fixedint.h does not recognize modern MSVC's stdint
// guard. Unreal has already loaded the standard types, so skip its fallback
// typedefs to avoid redefining int32_t/uint32_t.
#ifndef FIXEDINT_H_INCLUDED
#define FIXEDINT_H_INCLUDED
#endif

// Unreal defines these wrappers to suppress warnings in vendored code. Keep
// the engine-free test build source-compatible by providing empty fallbacks.
#if defined(UE_GAME) || defined(UE_EDITOR)
#include "HAL/Platform.h"
#endif

#ifndef THIRD_PARTY_INCLUDES_START
#define THIRD_PARTY_INCLUDES_START
#endif

#ifndef THIRD_PARTY_INCLUDES_END
#define THIRD_PARTY_INCLUDES_END
#endif
