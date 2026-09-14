using UnrealBuildTool;

public class SystemLockerNightflyer : ModuleRules
{
    public SystemLockerNightflyer(ReadOnlyTargetRules target) : base(target)
    {
        PCHUsage = PCHUsageMode.NoPCHs;
        // Keep the vendored C translation units isolated from the C++ core;
        // combining them in a unity build changes their compile environment.
        bUseUnity = false;

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
        // Resolves <nlohmann/json.hpp>, "ed25519/ed25519.h", and "micro-ecc/uECC.h".
        PrivateIncludePaths.Add(Path.Combine(ModuleDirectory, "Private", "Vendor"));
    }
}
