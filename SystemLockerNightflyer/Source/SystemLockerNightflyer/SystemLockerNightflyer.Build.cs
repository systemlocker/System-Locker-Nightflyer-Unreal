// Copyright (c) 2026 System Locker. All rights reserved.
using UnrealBuildTool;
using System.IO;

public class SystemLockerNightflyer : ModuleRules
{
    public SystemLockerNightflyer(ReadOnlyTargetRules target) : base(target)
    {
        PCHUsage = PCHUsageMode.NoPCHs;
        // Keep the vendored C translation units isolated from the C++ core;
        // combining them in a unity build changes their compile environment.
        bUseUnity = false;

        // Nightflyer's engine-independent core uses typed exceptions for
        // validation, transport failures, and state-machine rollback. Unreal
        // Game targets disable unwind semantics by default, so opt this module
        // in explicitly instead of compiling catch blocks without /EHsc.
        bEnableExceptions = true;

        CppStandard = CppStandardVersion.Cpp20;

        // The Blueprint header is public, so its UObject and Engine types must
        // also be public dependencies for game modules that include it.
        PublicDependencyModuleNames.AddRange(new string[] { "Core", "CoreUObject", "Engine" });
        PrivateDependencyModuleNames.AddRange(new string[] { "HTTP" });

        if (target.Platform == UnrealTargetPlatform.Win64)
        {
            PublicSystemLibraries.AddRange(new string[] {
                "advapi32.lib", "bcrypt.lib", "crypt32.lib", "ncrypt.lib", "ole32.lib"
            });
        }
        else if (target.Platform == UnrealTargetPlatform.Mac)
        {
            PublicFrameworks.AddRange(new string[] { "CoreFoundation", "Security" });
        }

        PublicIncludePaths.Add(Path.Combine(ModuleDirectory, "Public"));
        PrivateIncludePaths.Add(Path.Combine(ModuleDirectory, "Private"));
        // Third-party sources live directly under Source/ThirdParty for Fab's
        // plugin layout; this path resolves their project-relative includes.
        PrivateIncludePaths.Add(Path.GetFullPath(Path.Combine(ModuleDirectory, "..", "ThirdParty")));
    }
}
