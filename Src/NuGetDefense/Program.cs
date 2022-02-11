using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Threading.Tasks;
using MessagePack;
using NuGetDefense.NVD;

namespace NuGetDefense;

public static class Program
{
    /// <summary>
    ///     args[0] is expected to be the path to the project file.
    /// </summary>
    /// <param name="args"></param>
    private static int Main(string[] args)
    {
        var projFileOption = new Option<FileInfo>("--project-file", "Project or Solution File to scan");
        projFileOption.AddAlias("-p");
        projFileOption.AddAlias("--project");
        projFileOption.AddAlias("--solution");

        var targetFrameworkMonikerOption = new Option<string>("--target-framework-moniker", "Framework to use when detecting versions for 'sdk style' projects");
        targetFrameworkMonikerOption.AddAlias("--tfm");
        targetFrameworkMonikerOption.AddAlias("--framework");

        var settingsOption = new Option<FileInfo>("--settings-file", () => null, "Path to Settings File (ex. NuGetDefense.json)");
        settingsOption.AddAlias("--nugetdefense-settings");
        settingsOption.AddAlias("--nugetdefense-json");

        var vulnerabilityDataBinOption = new Option<FileInfo>("--vulnerability-data-bin", "Path to VulnerabilityData for NVD Scanner (ex. VulnerabilityData.bin)");
        vulnerabilityDataBinOption.AddAlias("--nvd-data");
        vulnerabilityDataBinOption.AddAlias("--nvd-data-bin");
        vulnerabilityDataBinOption.AddAlias("--nvd-bin");
        vulnerabilityDataBinOption.AddAlias("--vulnerability-bin");
        vulnerabilityDataBinOption.AddAlias("--vulnerability-data");

        var warnOnlyOption = new Option<bool>("--warn-only", () => false, "Disables errors that would break a build, but outputs warnings for each report");
        warnOnlyOption.AddAlias("--do-not-break");
        warnOnlyOption.AddAlias("--warn");

        var checkTransitiveDependenciesOption = new Option<bool>("--check-transitive-dependencies", () => true, "Enables scanning of transitive dependencies");
        checkTransitiveDependenciesOption.AddAlias("--check-transitive");
        checkTransitiveDependenciesOption.AddAlias("--transitive");
        checkTransitiveDependenciesOption.AddAlias("--check-dependencies");
        checkTransitiveDependenciesOption.AddAlias("--dependencies");

        var checkProjectReferencesOption = new Option<bool>("--check-project-references", () => false, "Enables scanning projects referenced by the target project");
        checkProjectReferencesOption.AddAlias("--check-referenced-projects");
        checkProjectReferencesOption.AddAlias("--check-referenced");
        checkProjectReferencesOption.AddAlias("--check-references");
        checkProjectReferencesOption.AddAlias("--references");
        checkProjectReferencesOption.AddAlias("--referenced-projects");

        var ignoredCvesOption = new Option<string[]>("--ignore-cves", Array.Empty<string>, "Adds listed vulnerabilities to a list that is ignored when reporting");
        ignoredCvesOption.AddAlias("--ignore-vulns");

        var ignorePackagesOption = new Option<string[]>("--ignore-packages", Array.Empty<string>, "Adds names to a list of packages to ignore");

        var cacheLocationOption = new Option<string>("--cache-location", "location used to retrieve the cache");
        var rootCommand = new RootCommand
        {
            projFileOption,
            targetFrameworkMonikerOption,
            settingsOption,
            vulnerabilityDataBinOption,
            warnOnlyOption,
            checkTransitiveDependenciesOption,
            checkProjectReferencesOption,
            ignorePackagesOption,
            ignoredCvesOption,
            cacheLocationOption
        };

        var NvdUpdateCommand = new Command("Update", "Updates the Embedded Offline Vulnerability source");
        var RecreateNVDCommand = new Command("Recreate-NVD", "Recreates the NVD at the specified location");
        NvdUpdateCommand.Handler = CommandHandler.Create<InvocationContext>(Update);
        RecreateNVDCommand.Handler = CommandHandler.Create<string, InvocationContext>(RecreateNVD);
        rootCommand.Add(NvdUpdateCommand);
        rootCommand.Add(RecreateNVDCommand);

        rootCommand.Handler = CommandHandler.Create<FileInfo, string, FileInfo, FileInfo, bool, bool, bool, string[], string[], string, InvocationContext>(Scan);
        return rootCommand.InvokeAsync(args).Result;
    }

    private static void Update(InvocationContext commandContext)
    {
        var str = Path.Combine(Path.GetDirectoryName(AppContext.BaseDirectory), "VulnerabilityData.bin");
        var dateTime = DateTime.Now.Add(TimeSpan.FromMinutes(5));
        bool flag;
        Dictionary<string, Dictionary<string, VulnerabilityEntry>> _nvdDict = new();
        do
        {
            try
            {
                var fileStream = File.Open(str, FileMode.Open, FileAccess.Read);
                flag = false;
                var options = MessagePackSerializerOptions.Standard.WithCompression(MessagePackCompression.Lz4BlockArray).WithSecurity(MessagePackSecurity.UntrustedData);
                _nvdDict = MessagePackSerializer.Deserialize<Dictionary<string, Dictionary<string, VulnerabilityEntry>>>(fileStream, options);
                fileStream.Close();
            }
            catch (Exception ex)
            {
                flag = DateTime.Now <= dateTime;
                if (!flag) throw new TimeoutException($"Reading vulnerability data failed:'{str}'", ex);
            }
        } while (flag);

        var result1 = FeedUpdater.GetRecentFeedAsync().Result;
        var result2 = FeedUpdater.GetModifiedFeedAsync().Result;
        FeedUpdater.AddFeedToVulnerabilityData(result1, _nvdDict);
        FeedUpdater.AddFeedToVulnerabilityData(result2, _nvdDict);
        VulnerabilityData.SaveToBinFile(_nvdDict, "VulnerabilityData.bin", TimeSpan.FromMinutes(5));
    }

    public static async Task RecreateNVD(string VulnDataFile, InvocationContext commandContext)
    {
        var vulnDict =
            new Dictionary<string, Dictionary<string, VulnerabilityEntry>>();
        await foreach (var feed in FeedUpdater.GetFeedsAsync())
            FeedUpdater.AddFeedToVulnerabilityData(feed, vulnDict);
        vulnDict.MakeCorrections();

        VulnerabilityData.SaveToBinFile(vulnDict, VulnDataFile, TimeSpan.FromMinutes(10));
    }

    public static void MakeCorrections(this Dictionary<string, Dictionary<string, VulnerabilityEntry>> vulnDict)
    {
        if (vulnDict.ContainsKey("nlog"))
            vulnDict["nlog"].Remove("CVE-1999-1278");
        if (vulnDict.ContainsKey("twilio"))
            vulnDict["twilio"].Remove("CVE-2014-9023");
    }

    public static void Scan(FileInfo projectFile,
        string tfm,
        FileInfo settingsFile,
        FileInfo vulnDataFile,
        bool warnOnly,
        bool checkTransitiveDependencies,
        bool checkReferencedProjects,
        string[] ignorePackages,
        string[] ignoreCves,
        string? cacheLocation,
        InvocationContext commandContext)
    {
        if(settingsFile is null && projectFile is null) Console.WriteLine("Run `nugetdefense -?` for usage information");
        else
        {
            commandContext.ExitCode = new Scanner().Scan(new()
            {
                CheckReferencedProjects = checkReferencedProjects,
                CheckTransitiveDependencies = checkReferencedProjects,
                IgnoreCves = ignoreCves,
                IgnorePackages = ignorePackages,
                ProjectFile = projectFile,
                SettingsFile = settingsFile,
                Cache = VulnerabilityCache.GetSqliteCache(cacheLocation)
            });
        }
    }
}