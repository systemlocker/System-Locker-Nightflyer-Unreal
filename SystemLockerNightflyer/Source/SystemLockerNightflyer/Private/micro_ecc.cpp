// Copyright (c) 2026 System Locker. All rights reserved.
#include "ThirdPartyCompilation.h"
// UnrealBuildTool compiles module-local C++ files. Include the vendor source
// from Source/ThirdParty here without copying third-party code into Private.
THIRD_PARTY_INCLUDES_START
extern "C" {
#include "../../ThirdParty/micro-ecc/uECC.c"
}
THIRD_PARTY_INCLUDES_END
