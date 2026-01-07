using System;
using System.Collections.Generic;
using System.CommandLine;
using System.IO;
using System.Threading.Tasks;
using MessagePack;
using NuGetDefense.Configuration;
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
        var projFileOption = new Option<FileInfo>("--project-file", 
            ["-p", "--project", "--solution"])
        {
            Description = "Project or Solution File to scan"
        };

        var targetFrameworkMonikerOption = new Option<string>("--target-framework-moniker", 
            ["--tfm", "--framework"])
        {
            Description = "Framework to use when detecting versions for 'sdk style' projects"
        };

        var settingsOption = new Option<FileInfo?>("--settings-file", 
            ["--nugetdefense-settings", "--nugetdefense-json"])
        {
            Description = "Path to Settings File (ex. NuGetDefense.json)",
            DefaultValueFactory = _ => null
        };

        var warnOnlyOption = new Option<bool>("--warn-only", 
            ["--do-not-break", "--warn"])
        {
            Description = "Disables errors that would break a build, but outputs warnings for each report",
            DefaultValueFactory = _ => false
        };

        var checkTransitiveDependenciesOption = new Option<bool>("--check-transitive-dependencies", 
            ["--check-transitive", "--transitive", "--check-dependencies", "--dependencies"])
        {
            Description = "Enables scanning of transitive dependencies",
            DefaultValueFactory = _ => true
        };

        var checkProjectReferencesOption = new Option<bool>("--check-project-references", 
            ["--check-referenced-projects", "--check-referenced", "--check-references", "--references", "--referenced-projects"])
        {
            Description = "Enables scanning projects referenced by the target project",
            DefaultValueFactory = _ => false
        };

        var ignoredCvesOption = new Option<string[]>("--ignore-cves",
            ["--ignore-vulns"])
        {
            Description = "Adds listed vulnerabilities to a list that is ignored when reporting",
            DefaultValueFactory = _ => [],
            AllowMultipleArgumentsPerToken = true
        };

        var ignorePackagesOption = new Option<string[]>("--ignore-packages")
        {
            Description = "Adds names to a list of packages to ignore",
            DefaultValueFactory = _ => [],
            AllowMultipleArgumentsPerToken = true
        };

        var cacheLocationOption = new Option<string>("--cache-location")
        {
            Description = "location used to retrieve the cache"
        };

        var apiKeyOption = new Option<string>("--api-key")
        {
            Description = "NVD API key"
        };
        
        var vulnDataFileOption = new Option<FileInfo?>("--vuln-data-file")
        {
            Description = "Path to use for the vuln data file",
            DefaultValueFactory = _ => null
        };

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
            vulnDataFileOption
        };
        nvdUpdateCommand.SetAction(parseResult =>
        {
            Update(parseResult.GetValue(settingsOption),
                parseResult.GetValue(apiKeyOption),
                parseResult.GetValue(vulnDataFileOption));
        });

        var recreateNVDCommand = new Command("Recreate-NVD", "Recreates the Offline NVD Vulnerability source")
        {
            settingsOption,
            apiKeyOption,
            vulnDataFileOption,
        };
        recreateNVDCommand.SetAction(async parseResult =>
        {
            await RecreateNVDAsync(parseResult.GetValue(settingsOption),
                parseResult.GetValue(apiKeyOption),
                parseResult.GetValue(vulnDataFileOption));
        });

        rootCommand.Add(nvdUpdateCommand);
        rootCommand.Add(recreateNVDCommand);

        rootCommand.SetAction(parseResult =>
        {
            return Scan(parseResult.GetValue(projFileOption),
                parseResult.GetValue(targetFrameworkMonikerOption)!,
                parseResult.GetValue(settingsOption),
                parseResult.GetValue(warnOnlyOption),
                parseResult.GetValue(checkTransitiveDependenciesOption),
                parseResult.GetValue(checkProjectReferencesOption),
                parseResult.GetValue(ignorePackagesOption)!,
                parseResult.GetValue(ignoredCvesOption)!,
                parseResult.GetValue(cacheLocationOption));
        });

        return rootCommand.Parse(args).InvokeAsync().Result;
    }

    private static async void Update(FileInfo? vulnDataFile, string? apiKey, FileInfo? settingsFile)
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
                await RecreateNVDAsync(new (Scanner.VulnerabilityDataBin), apiKey, settingsFile);
                return;
            }
        }
        else if (!vulnDataFile.Exists)
        {
            // NVD Data does not exist, create it.
            await RecreateNVDAsync(vulnDataFile, apiKey, settingsFile);
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

    public static async Task RecreateNVDAsync(FileInfo? vulnDataFile, string? apiKey, FileInfo? settingsFile)
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

    public static int Scan(FileInfo? projectFile,
        string tfm,
        FileInfo? settingsFile,
        bool warnOnly,
        bool checkTransitiveDependencies,
        bool checkReferencedProjects,
        string[] ignorePackages,
        string[] ignoreCves,
        string? cacheLocation)
    {
        if (projectFile is null) { Console.WriteLine("Run `nugetdefense -?` for usage information"); return -1; }
        else
            return new Scanner().Scan(new()
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