using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using ByteDev.DotNet.Project;
using ByteDev.DotNet.Solution;
using MessagePack;
using NuGet.Versioning;
using NuGetDefense.Configuration;
using NuGetDefense.Core;
using NuGetDefense.NVD;
using Serilog;

namespace NuGetDefense;

public class Scanner
{
    public const string Version = "4.1.1";
    public const string UserAgentString = @$"NuGetDefense/{Version}";
    public const string DefaultSettingsFileName = "NuGetDefense.json";
    public const string DefaultVulnerabilityDataFileName = "VulnerabilityData.bin";

    /// <summary>
    ///     Folder for NuGetDefense configuration and caching
    /// </summary>
    private static readonly string NuGetDefenseFolder =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create), ".nugetDefense");

    /// <summary>
    ///     The global vulnerability data used by NuGetDefense
    /// </summary>
    public static readonly string VulnerabilityDataBin = Path.Combine(NuGetDefenseFolder, DefaultVulnerabilityDataFileName);

    /// <summary>
    ///     The global NuGetDefense.json path
    /// </summary>
    public static readonly string GlobalConfigFile = Path.Combine(NuGetDefenseFolder, DefaultSettingsFileName);

    private string _nuGetFile;
    private string _projectFileName;
    private Dictionary<string, NuGetPackage[]> _projects;
    private Settings _settings;
    private int NumberOfVulnerabilities;

    /// <summary>
    ///     Scans the provided project's NuGet Dependencies for known vulnerabilities
    /// </summary>
    /// <returns></returns>
    public int Scan(ScanOptions options)
    {
        int exitCode;
        NumberOfVulnerabilities = 0;
        _projects = [];
        try
        {
            LoadSettings(options);
            ConfigureLogging();
            ScanVulnerabilities(options);
            exitCode = _settings.WarnOnly ? 0 : NumberOfVulnerabilities;
        }
        catch (Exception e)
        {
            exitCode = -1;
            Debug.WriteLine(e);
        }

        return exitCode;
    }

    private void LoadSettings(ScanOptions options)
    {
        try
        {
            if (options.SettingsFile == null)
            {
                
                Log.Logger.Information("Determining settings file location");
                string? settingsFilePath = null;
                if (!string.IsNullOrWhiteSpace(options.ProjectFile?.DirectoryName))
                {
                    var projectSettingsPath = Path.Combine(options.ProjectFile?.DirectoryName, DefaultSettingsFileName);
                    // Check Project Directory First for Settings
                    if (File.Exists(projectSettingsPath))
                    { 
                        Log.Logger.Information($"NuGetDefense: Using project level settings file at: {projectSettingsPath}");

                        settingsFilePath = projectSettingsPath;
                    }
                    else if (File.Exists(Path.Combine(Directory.GetParent(projectSettingsPath)?.Parent?.FullName ?? "", DefaultSettingsFileName)))
                    { 
                        // Use Parent Directory of Project if the Settings File exists there instead
                        settingsFilePath = Path.Combine(Directory.GetParent(projectSettingsPath)?.FullName ?? "", DefaultSettingsFileName);
                        Log.Logger.Information($"NuGetDefense: Using project level settings file at parent folder: {settingsFilePath}");
                    }
                }

                // If SettingsPath is still not decided, use the global settings file or create it.
                if (string.IsNullOrWhiteSpace(settingsFilePath)) 
                {

                    Log.Logger.Information($"NuGetDefense: Using global level settings file at: {GlobalConfigFile}");
                    settingsFilePath = GlobalConfigFile;
                }

                _settings = Settings.LoadSettings(settingsFilePath);
            }
            else
            {
                Log.Logger.Information($"NuGetDefense: Using argument-driven settings file at: {options.SettingsFile.FullName}");
                _settings = Settings.LoadSettingsFile(options.SettingsFile.FullName);
            }

            _settings.WarnOnly = _settings.WarnOnly || options.WarnOnly;
            _settings.CheckTransitiveDependencies =
                _settings.CheckTransitiveDependencies && options.CheckTransitiveDependencies;
            _settings.CheckReferencedProjects = _settings.CheckReferencedProjects || options.CheckReferencedProjects;
            _settings.ErrorSettings.IgnoredPackages = _settings.ErrorSettings.IgnoredPackages
                .Union(options.IgnorePackages.Select(p => new NuGetPackage { Id = p })).ToArray();
            _settings.ErrorSettings.IgnoredCvEs =
                _settings.ErrorSettings.IgnoredCvEs.Union(options.IgnoreCves).ToArray();

            // TODO: Ideally we will add a check for "CacheType" here when another type of cache is added
            options.Cache ??= VulnerabilityCache.GetSqliteCache(_settings.CacheLocation);

            _projectFileName = options.ProjectFile!.Name;
        }
        catch (Exception e)
        {
            var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error,
                $"Encountered a fatal exception while load settings. Exception: {e}");
            Console.WriteLine(msBuildMessage);
            Log.Logger.Fatal(msBuildMessage);

            throw;
        }
    }

    private void ScanVulnerabilities(ScanOptions options)
    {
        try
        {
            var projectFullName = options.ProjectFile?.FullName;
            if (options.ProjectFile != null && options.ProjectFile.Extension.Equals(".sln", StringComparison.OrdinalIgnoreCase))
            {
                var projects = DotNetSolution.Load(projectFullName).Projects.Where(p => !p.Type.IsSolutionFolder).Select(p => p.Path).ToArray();
                var specificFramework = !string.IsNullOrWhiteSpace(options.Tfm);
                if (specificFramework) Log.Logger.Information("Target Framework: {framework}", options.Tfm);

                _projects = LoadMultipleProjects(projectFullName, projects, specificFramework, options.Tfm, true);
            }
            else if (_settings.CheckReferencedProjects)
            {
                var projects = new List<string> { projectFullName };
                GetProjectsReferenced(in projectFullName, in projects);
                var specificFramework = !string.IsNullOrWhiteSpace(options.Tfm);
                if (specificFramework) Log.Logger.Information("Target Framework: {framework}", options.Tfm);

                _projects = LoadMultipleProjects(projectFullName, projects.ToArray(), specificFramework, options.Tfm);
            }
            else
            {
                var nugetFile = new NuGetFile(projectFullName);
                _nuGetFile = nugetFile.Path;

                Log.Logger.Verbose("NuGetFile Path: {nugetFilePath}", _nuGetFile);

                Log.Logger.Information("Target Framework: {framework}", string.IsNullOrWhiteSpace(options.Tfm) ? "Undefined" : options.Tfm);
                Log.Logger.Verbose("Loading Packages");
                Log.Logger.Verbose("Transitive Dependencies Included: {CheckTransitiveDependencies}", _settings.CheckTransitiveDependencies);

                if (_settings.CheckTransitiveDependencies && nugetFile.PackagesConfig)
                {
                    var projects = DotNetProject.Load(projectFullName).ProjectReferences.Select(p => p.FilePath).ToArray();
                    var specificFramework = !string.IsNullOrWhiteSpace(options.Tfm);
                    if (specificFramework) Log.Logger.Information("Target Framework: {framework}", options.Tfm);

                    _projects = LoadMultipleProjects(projectFullName, projects, specificFramework, options.Tfm);
                }
                else
                {
                    _projects = new();
                    _projects.Add(nugetFile.Path, nugetFile.LoadPackages(options.Tfm, _settings.CheckTransitiveDependencies).Values.ToArray());
                }
            }

            GetNonSensitivePackages(out var nonSensitivePackages);
            if (_settings.ErrorSettings.IgnoredPackages is { Length: > 0 })
                foreach (var (proj, packages) in _projects.ToArray())
                {
                    UtilityMethods.IgnorePackages(in packages, _settings.ErrorSettings.IgnoredPackages, out var projPackages);
                    _projects[proj] = projPackages;
                }

            Log.Logger.Information("Loaded {packageCount} packages", _projects.Sum(p => p.Value.Length));

            if (_settings.ErrorSettings.BlockedPackages is { Length: > 0 }) CheckBlockedPackages();
            if (_settings.ErrorSettings.AllowedPackages is { Length: > 0 }) CheckAllowedPackages();
            Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = null;
            var nonSensitivePackageIDs = nonSensitivePackages.SelectMany(p => p.Value).ToArray();
            if (_settings.OssIndex.Enabled)
            {
                const string ossIndexSourceId = "OSSIndex";
                var uncachedPkgs = options.Cache.GetUncachedPackages(nonSensitivePackageIDs, TimeSpan.FromDays(1), ossIndexSourceId, out var cachedPackages);
                var modUncached = uncachedPkgs.Count % 128;
                if (modUncached > 0 && cachedPackages.Length > 0)
                {
                    var rescanCount = Math.Min(128 - modUncached, cachedPackages.Length);
                    for (var i = cachedPackages.Length - 1; i >= 0; i--)
                    {
                        uncachedPkgs.Add(cachedPackages[i]);
                    }

                    cachedPackages = cachedPackages[..^rescanCount];
                }
                // Round out the calls to have a full set of packages each to refresh oldest cached packages
                if (uncachedPkgs.Count > 0) uncachedPkgs.AddRange(cachedPackages.Take(uncachedPkgs.Count % 128));

                Log.Logger.Verbose("Checking with OSSIndex for Vulnerabilities");
                vulnDict =
                    new OSSIndex.Scanner(_nuGetFile, _settings.OssIndex.BreakIfCannotRun, UserAgentString, _settings.OssIndex.Username, _settings.OssIndex.ApiToken)
                        .GetVulnerabilitiesForPackages(uncachedPkgs.ToArray());
                if (vulnDict != null)
                    // If we failed to update the OSS Index data don't clear out old cached data as that will
                    // increase the number of requests next time, increasing the liklihood of further
                    // TooManyRequeusts responses.
                    options.Cache.UpdateCache(vulnDict, uncachedPkgs, ossIndexSourceId);

                // Skipping the packages we refreshed
                options.Cache.GetPackagesCachedVulnerabilitiesForSource(cachedPackages.Skip(uncachedPkgs.Count % 128), ossIndexSourceId, ref vulnDict);
            }

            if (_settings.GitHubAdvisoryDatabase.Enabled)
            {
                if (string.IsNullOrWhiteSpace(_settings.GitHubAdvisoryDatabase.ApiToken))
                {
                    var msBuildMessage = MsBuild.Log(_nuGetFile, _settings.GitHubAdvisoryDatabase.BreakIfCannotRun ? MsBuild.Category.Error : MsBuild.Category.Warning,
                        "GitHub Security Advisory Database Access Requires a GitHub Personal Access Toke (no special permissions): https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token");
                    Console.WriteLine(msBuildMessage);
                    Log.Logger.Error(msBuildMessage);
                }
                else
                {
                    const string gitHubAdvisoryDatabaseSourceId = "GitHubSecurityAdvisoryDatabase";
                    var uncachedPkgs = options.Cache.GetUncachedPackages(nonSensitivePackageIDs, TimeSpan.FromDays(1), gitHubAdvisoryDatabaseSourceId, out var cachedPackages);
                    var modUncached = uncachedPkgs.Count % 128;
                    if (modUncached > 0 && cachedPackages.Length > 0)
                    {
                        var rescanCount = Math.Min(128 - modUncached, cachedPackages.Length);
                        for (var i = cachedPackages.Length - 1; i >= 0; i--)
                        {
                            uncachedPkgs.Add(cachedPackages[i]);
                        }

                        cachedPackages = cachedPackages[..^rescanCount];
                    }
                    Log.Logger.Verbose("Checking the GitHub Security Advisory Database for Vulnerabilities");
                    var ghsaVulnDict =
                        new GitHubAdvisoryDatabase.Scanner(_nuGetFile, _settings.GitHubAdvisoryDatabase.ApiToken, _settings.GitHubAdvisoryDatabase.BreakIfCannotRun)
                            .GetVulnerabilitiesForPackages(uncachedPkgs.ToArray());
                    options.Cache.UpdateCache(ghsaVulnDict, uncachedPkgs, gitHubAdvisoryDatabaseSourceId);

                    if (vulnDict == null)
                        vulnDict = ghsaVulnDict;
                    else
                        MergeVulnDict(ref vulnDict, ref ghsaVulnDict);
                    options.Cache.GetPackagesCachedVulnerabilitiesForSource(cachedPackages, gitHubAdvisoryDatabaseSourceId, ref vulnDict);
                }
            }

            if (_settings.NVD.Enabled)
            {
                Log.Logger.Verbose("Checking the embedded NVD source for Vulnerabilities");

                if (File.Exists(VulnerabilityDataBin))
                {
                }

                foreach (var (_, pkgs) in _projects)
                    vulnDict =
                        new NVD.Scanner(_nuGetFile, TimeSpan.FromSeconds(_settings.NVD.TimeoutInSeconds),
                                new(_settings.NvdApi.ApiToken, UserAgentString),
                                new(),
                                _settings.NVD.BreakIfCannotRun, _settings.NVD.SelfUpdate)
                            .GetVulnerabilitiesForPackages(pkgs,
                                vulnDict);
            }

            if (_settings.ErrorSettings.IgnoredCvEs is { Length: > 0 })
            {
                Log.Logger.Information("ignoring {ignoredCVECount} Vulnerabilities",
                    _settings.ErrorSettings.IgnoredCvEs.Length);
                VulnerabilityData.IgnoreCVEs(vulnDict, _settings.ErrorSettings.IgnoredCvEs);
            }

            if (vulnDict != null) ReportVulnerabilities(vulnDict);
        }
        catch (Exception e)
        {
            var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error,
                $"Encountered a fatal exception while checking for Dependencies in {_nuGetFile}. Exception: {e}");
            Console.WriteLine(msBuildMessage);
            Log.Logger.Fatal(msBuildMessage);

            throw;
        }
    }

    private async Task<Dictionary<string, Dictionary<string, VulnerabilityEntry>>> ReadFromBinFileAsync(string vulnDataFile)
    {
        var lz4Options = MessagePackSerializerOptions.Standard.WithCompression(MessagePackCompression.Lz4BlockArray)
            .WithSecurity(MessagePackSecurity.UntrustedData);

        if (!File.Exists(vulnDataFile))
            // TODO: Pass in API Key
            return await VulnerabilityDataUpdater.CreateNewVulnDataBin(vulnDataFile, new(null, UserAgentString));

        var startDateTime = DateTime.Now.AddSeconds(_settings.NVD.TimeoutInSeconds);
        bool ableToReadVulnerabilityData;
        do
        {
            try
            {
                await using var nvdData = File.Open(vulnDataFile, FileMode.Open, FileAccess.Read);
                return await MessagePackSerializer.DeserializeAsync<Dictionary<string, Dictionary<string, VulnerabilityEntry>>>(nvdData, lz4Options);
            }
            catch (Exception e)
            {
                ableToReadVulnerabilityData = DateTime.Now <= startDateTime;
                if (!ableToReadVulnerabilityData && _settings.NVD.BreakIfCannotRun)
                    throw new TimeoutException($"Reading vulnerability data failed:'{vulnDataFile}'", e);
            }
        } while (ableToReadVulnerabilityData);

        return new();
    }

    private void MergeVulnDict(ref Dictionary<string, Dictionary<string, Vulnerability>> vulnDict, ref Dictionary<string, Dictionary<string, Vulnerability>> vulnDict2)
    {
        foreach (var vulnDict2Key in vulnDict2.Keys)
            if (vulnDict.ContainsKey(vulnDict2Key))
            {
                foreach (var cve in vulnDict2[vulnDict2Key].Keys)
                    if (!vulnDict[vulnDict2Key].ContainsKey(cve))
                        vulnDict[vulnDict2Key].Add(cve, vulnDict2[vulnDict2Key][cve]);
            }
            else
            {
                vulnDict.Add(vulnDict2Key, vulnDict2[vulnDict2Key]);
            }
    }

    private static void GetProjectsReferenced(in string proj, in List<string> projectList)
    {
        var dir = Path.GetDirectoryName(proj);
        foreach (var referencedProj in DotNetProject.Load(proj).ProjectReferences
                     .Select(p => Path.Combine(dir!, p.FilePath.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar))))
        {
            if (!projectList.Contains(referencedProj))
                projectList.Add(referencedProj);
            GetProjectsReferenced(in referencedProj, in projectList);
        }
    }

    private Dictionary<string, NuGetPackage[]> LoadMultipleProjects(string topLevelProject, IReadOnlyList<string> projects, bool specificFramework, string targetFramework,
        bool solutionFile = false)
    {
        var projectPackages = new Dictionary<string, NuGetPackage[]>();
        for (var i = 0; i < projects.Count; i++)
        {
            var pkgs = new List<NuGetPackage>();

            var project = projects[i];
            // If the project is an SSIS project, skip it
            if (project.EndsWith(".dtproj")) continue;
            var path = Path.Combine(Path.GetDirectoryName(topLevelProject)!, project
                .Replace('\\', Path.DirectorySeparatorChar)
                .Replace('/', Path.DirectorySeparatorChar));

            var proj = DotNetProject.Load(path);
            if (!specificFramework && proj.Format == ProjectFormat.New)
            {
                if (proj.ProjectTargets.Any())
                {
                    var monikersListBuilder = new StringBuilder();
                    var monikers = proj.ProjectTargets.Select(t => t.Moniker).ToArray();
                    monikersListBuilder.Append(monikers[0]);
                    for (var index = 1; index < monikers.Length; index++) monikersListBuilder.Append($", {monikers[index]}");

                    Log.Logger.Information("Target Frameworks for {project}: {frameworks}", project, monikersListBuilder.ToString());
                    var nugetFile = new NuGetFile(path);
                    pkgs.AddDistinctPackages(monikers.SelectMany(m => nugetFile.LoadPackages(m, _settings.CheckTransitiveDependencies).Values));
                }
                else
                {
                    Log.Logger.Information("No Target Frameworks found in {project}", project);
                }
            }
            else
            {
                pkgs.AddDistinctPackages(new NuGetFile(path).LoadPackages(targetFramework, _settings.CheckTransitiveDependencies).Values);
            }

            projectPackages.Add(path, pkgs.ToArray());
        }

        var nuGetFile = new NuGetFile(topLevelProject);
        _nuGetFile = nuGetFile.Path;

        if (!solutionFile && !projectPackages.ContainsKey(topLevelProject))
            projectPackages.Add(topLevelProject, nuGetFile.LoadPackages(targetFramework, _settings.CheckTransitiveDependencies).Values.ToArray());

        return projectPackages;
    }

    /// <summary>
    ///     Escapes all characters for Regex, then replaces '*' with '.*' (Regex wild Card for 0 or more of any character)
    /// </summary>
    /// <param name="nonSensitives"></param>
    /// <returns>a list of packages that do not match the wild card strings in SensitivePackages</returns>
    public void GetNonSensitivePackages(out Dictionary<string, NuGetPackage[]> nonSensitives)
    {
        nonSensitives = new();
        var sensitiveRegexSet = _settings.SensitivePackages.Select(sp => Regex.Escape(sp).Replace(@"\*", ".*")).ToArray();
        foreach (var (project, packages) in _projects) nonSensitives.Add(project, packages.Where(p => !sensitiveRegexSet.Any(x => Regex.IsMatch(p.Id, x))).ToArray());
    }

    private void CheckAllowedPackages()
    {
        Log.Logger.Verbose("Checking Allowed Packages");

        foreach (var (project, packages) in _projects)
        foreach (var pkg in packages.Where(p => _settings.ErrorSettings.AllowedPackages != null && !_settings.ErrorSettings.AllowedPackages.Any(b =>
                     b.Id == p.Id &&
                     (string.IsNullOrWhiteSpace(b.Version) || VersionRange.Parse(p.Version).Satisfies(new(b.Version))))))
        {
            Log.Logger.Error("{packageName}:{version} was included in {nugetFile} but is not in the Allowed List", pkg.Id, pkg.Version, _nuGetFile);

            var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error, pkg.LineNumber, pkg.LinePosition,
                $"{pkg.Id} is not listed as an allowed package and may not be used in this project");
            Console.WriteLine(msBuildMessage);
            Log.Logger.Error(msBuildMessage);
        }
    }

    private void ReportVulnerabilities(Dictionary<string, Dictionary<string, Vulnerability>>? vulnDict)
    {
        if (vulnDict == null)
        {
            Log.Logger.Information("No Vulnerabilities found in {numberOfPackages} packages", _projects.Sum(p => p.Value.Length));
        }
        else
        {
            Log.Logger.Verbose("Building report of Vulnerabilities found in {numberOfPackages} packages", vulnDict.Keys.Count);
            var vulnReporter = new VulnerabilityReporter();

            foreach (var (project, packages) in _projects)
            {
                //TODO: Losing the right file somewhere here
                vulnReporter.BuildVulnerabilityTextReport(vulnDict, packages, project, _settings.WarnOnly,
                    _settings.ErrorSettings.Cvss3Threshold, out var projectNumberOfVulnerabilities);

                NumberOfVulnerabilities += projectNumberOfVulnerabilities;

                if (_settings.VulnerabilityReports.OutputTextReport) Log.Logger.Information(vulnReporter.VulnerabilityTextReport);
                if (vulnReporter.MsBuildMessages == null) continue;
                foreach (var msBuildMessage in vulnReporter.MsBuildMessages)
                {
                    Console.WriteLine(msBuildMessage);
                    Log.Logger.Debug(msBuildMessage);
                }
            }


            if (string.IsNullOrWhiteSpace(_settings.VulnerabilityReports.JsonReportPath) && string.IsNullOrWhiteSpace(_settings.VulnerabilityReports.XmlReportPath)) return;

            vulnReporter.BuildVulnerabilityReport(vulnDict, _projects, _settings.WarnOnly);
            if (!string.IsNullOrWhiteSpace(_settings.VulnerabilityReports.JsonReportPath))
            {
                var ops = new JsonSerializerOptions
                {
                    IgnoreReadOnlyProperties = true,
                    PropertyNameCaseInsensitive = true,
                    ReadCommentHandling = JsonCommentHandling.Skip,
                    WriteIndented = true
                };

                var contents = JsonSerializer.Serialize(vulnReporter.Report, ops);
                File.WriteAllText(_settings.VulnerabilityReports.JsonReportPath.Replace("{project}", _projectFileName), contents
                );
            }

            if (string.IsNullOrWhiteSpace(_settings.VulnerabilityReports.XmlReportPath)) return;
            var filename = _settings.VulnerabilityReports.XmlReportPath.Replace("{project}", _projectFileName);
            var xmlTextWriter = new XmlTextWriter(File.Create(filename), Encoding.Default);
            var xmlSerializer = new XmlSerializer(typeof(VulnerabilityReport));
            xmlSerializer.Serialize(xmlTextWriter, vulnReporter.Report);
        }
    }

    private void ConfigureLogging()
    {
        if (!(_settings.Logs?.Length > 0)) return;
        var loggerConfiguration = new LoggerConfiguration();
        foreach (var log in _settings.Logs)
        {
            var file = log.OutPut.Replace("{project}", _projectFileName);
            loggerConfiguration.WriteTo.File(file,
                log.LogLevel,
                rollingInterval: log.RollingInterval);
        }

        loggerConfiguration.WriteTo.Console();
        Log.Logger = loggerConfiguration.CreateLogger();
        Log.Logger.Verbose("Logging Configured");
    }

    private void CheckBlockedPackages()
    {
        foreach (var (proj, pkgs) in _projects)
        foreach (var pkg in pkgs)
        {
            Log.Logger.Verbose("Checking to see if {packageName}:{version} is Blocked", pkg.Id, pkg.Version);

            var blockedPackage = _settings.ErrorSettings.BlockedPackages.FirstOrDefault(b =>
                b.Package.Id == pkg.Id &&
                (string.IsNullOrWhiteSpace(b.Package.Version) || VersionRange.Parse(pkg.Version).Satisfies(new(b.Package.Version))));
            if (blockedPackage == null)
            {
                Log.Logger.Verbose("{packageName}:{version} is not Blocked", pkg.Id, pkg.Version);
                continue;
            }

            var msBuildMessage = MsBuild.Log(proj, MsBuild.Category.Error, pkg.LineNumber, pkg.LinePosition,
                $"{pkg.Id}: {(string.IsNullOrEmpty(blockedPackage.CustomErrorMessage) ? "has been blocked and may not be used in this project" : blockedPackage.CustomErrorMessage)}");
            Console.WriteLine(msBuildMessage);
            Log.Logger.Error(msBuildMessage);
        }
    }
}