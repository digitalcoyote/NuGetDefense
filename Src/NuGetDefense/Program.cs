using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.NamingConventionBinder;
using System.IO;
using System.Threading.Tasks;
using MessagePack;
using NuGetDefense.Configuration;
using NuGetDefense.NVD;
using NugetDefense.NVD.API;

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

        var settingsOption = new Option<FileInfo?>("--settings-file", () => null, "Path to Settings File (ex. NuGetDefense.json)");
        settingsOption.AddAlias("--nugetdefense-settings");
        settingsOption.AddAlias("--nugetdefense-json");

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

        var apiKeyOption = new Option<string>("--api-key", "NVD API key");
        
        var vulnDataFileOption = new Option<FileInfo?>("--vuln-data-file", "Path to use for the vuln data file");
        var rootCommand = new RootCommand
        {
            projFileOption,
            targetFrameworkMonikerOption,
            settingsOption,
            warnOnlyOption,
            checkTransitiveDependenciesOption,
            checkProjectReferencesOption,
            ignorePackagesOption,
            ignoredCvesOption,
            cacheLocationOption
        };

        var nvdUpdateCommand = new Command("Update", "Updates the Offline NVD Vulnerability source")
        {
            settingsOption,
            apiKeyOption,
            vulnDataFileOption,
        };
        
        var recreateNVDCommand = new Command("Recreate-NVD", "Recreates the Offline NVD Vulnerability source")
        {
            settingsOption,
            apiKeyOption,
            vulnDataFileOption,
        };
        nvdUpdateCommand.Handler = CommandHandler.Create<FileInfo?, string, FileInfo?, InvocationContext>(Update);
        recreateNVDCommand.Handler = CommandHandler.Create<FileInfo?, string, FileInfo?, InvocationContext>(RecreateNVDAsync);
        rootCommand.Add(nvdUpdateCommand);
        rootCommand.Add(recreateNVDCommand);

        rootCommand.Handler = CommandHandler.Create<FileInfo, string, FileInfo, bool, bool, bool, string[], string[], string, InvocationContext>(Scan);
        return rootCommand.InvokeAsync(args).Result;
    }

    private static async void Update(FileInfo? vulnDataFile, string? apiKey, FileInfo? settingsFile,  InvocationContext commandContext)
    {
        
        if (string.IsNullOrWhiteSpace(apiKey)  )
        {
            if (settingsFile is { Exists: true })
            {
                apiKey = Settings.LoadSettingsFile(settingsFile.FullName).NvdApi.ApiToken;
            }
            else if(File.Exists(Scanner.GlobalConfigFile))
            {
                apiKey = Settings.LoadSettingsFile(Scanner.GlobalConfigFile).NvdApi.ApiToken;
            }
            else
            {
                Settings.CreateDefaultSettingsFile(Scanner.GlobalConfigFile);
            }
        }
        if (vulnDataFile == null)
        {
            if (File.Exists(Scanner.DefaultVulnerabilityDataFileName))
            {
                vulnDataFile = new(Scanner.DefaultVulnerabilityDataFileName);
            }
            else if (File.Exists(Scanner.VulnerabilityDataBin))
            {
                vulnDataFile = new(Scanner.VulnerabilityDataBin);
            }
            else
            {
                // NVD Data was not specified and does not exist in global location or in current directory
                await RecreateNVDAsync(new (Scanner.VulnerabilityDataBin), apiKey, settingsFile, commandContext);
                return;
            }
        }
        else if (!vulnDataFile.Exists)
        {
            // NVD Data does not exist, create it.
            await RecreateNVDAsync(vulnDataFile, apiKey, settingsFile, commandContext);
            return;
        }
        
        var dateTime = DateTime.Now.Add(TimeSpan.FromMinutes(5));
        bool flag;
        Dictionary<string, Dictionary<string, VulnerabilityEntry>> nvdDict = new();
        do
        {
            try
            {
                var fileStream = vulnDataFile.Open(FileMode.Open, FileAccess.Read);
                flag = false;
                var options = MessagePackSerializerOptions.Standard.WithCompression(MessagePackCompression.Lz4BlockArray).WithSecurity(MessagePackSecurity.UntrustedData);
                nvdDict = MessagePackSerializer.Deserialize<Dictionary<string, Dictionary<string, VulnerabilityEntry>>>(fileStream, options);
                fileStream.Close();
            }
            catch (Exception ex)
            {
                flag = DateTime.Now <= dateTime;
                if (!flag) throw new TimeoutException($"Reading vulnerability data failed:'{Scanner.VulnerabilityDataBin}'", ex);
            }
        } while (flag);

        await VulnerabilityDataUpdater.UpdateVulnerabilityDataFromApi(new (apiKey, Scanner.UserAgentString), new (){LastModStartDate = vulnDataFile.LastWriteTime}, nvdDict);
        VulnerabilityData.SaveToBinFile(nvdDict, Scanner.DefaultVulnerabilityDataFileName, TimeSpan.FromMinutes(5));
    }

    public static async Task RecreateNVDAsync(FileInfo? vulnDataFile, string? apiKey, FileInfo? settingsFile,  InvocationContext commandContext)
    {
        if (string.IsNullOrWhiteSpace(apiKey)  )
        {
            if (settingsFile is { Exists: true })
            {
                apiKey = Settings.LoadSettingsFile(settingsFile.FullName).NvdApi.ApiToken;
            }
            else if(File.Exists(Scanner.GlobalConfigFile))
            {
                apiKey = Settings.LoadSettingsFile(Scanner.GlobalConfigFile).NvdApi.ApiToken;
            }
            else
            {
                Settings.LoadSettings();
            }
        }
        
        vulnDataFile ??= new (Scanner.VulnerabilityDataBin);

        var vulnDict = new Dictionary<string, Dictionary<string, VulnerabilityEntry>>();
        await VulnerabilityDataUpdater.CreateNewVulnDataBin(vulnDataFile.FullName, new (apiKey, Scanner.UserAgentString));
    }

    public static void MakeCorrections(this Dictionary<string, Dictionary<string, VulnerabilityEntry>> vulnDict)
    {
        if (vulnDict.ContainsKey("nlog"))
            vulnDict["nlog"].Remove("CVE-1999-1278");
        if (vulnDict.ContainsKey("twilio"))
            vulnDict["twilio"].Remove("CVE-2014-9023");
    }

    public static void Scan(FileInfo? projectFile,
        string tfm,
        FileInfo? settingsFile,
        bool warnOnly,
        bool checkTransitiveDependencies,
        bool checkReferencedProjects,
        string[] ignorePackages,
        string[] ignoreCves,
        string? cacheLocation,
        InvocationContext commandContext)
    {
        if (projectFile is null) Console.WriteLine("Run `nugetdefense -?` for usage information");
        else
            commandContext.ExitCode = new Scanner().Scan(new()
            {
                CheckReferencedProjects = checkReferencedProjects,
                CheckTransitiveDependencies = checkTransitiveDependencies,
                IgnoreCves = ignoreCves,
                IgnorePackages = ignorePackages,
                ProjectFile = projectFile,
                SettingsFile = settingsFile,
                Tfm = tfm,
                WarnOnly = warnOnly,
                Cache = VulnerabilityCache.GetSqliteCache(cacheLocation)
            });
    }
}