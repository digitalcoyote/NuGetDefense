using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;
using ByteDev.DotNet.Project;
using ByteDev.DotNet.Solution;
using NuGet.Versioning;
using NuGetDefense.Configuration;
using NuGetDefense.Core;
using NuGetDefense.OSSIndex;
using Serilog;
using static NuGetDefense.UtilityMethods;

namespace NuGetDefense
{
    internal static class Program
    {
        private static readonly string UserAgentString = @$"NuGetDefense/{Version}";

        private const string Version = "2.0.2";

        private static string _nuGetFile;
        private static string _projectFileName;
        private static NuGetPackage[] _pkgs;
        private static Settings _settings;

        /// <summary>
        ///     args[0] is expected to be the path to the project file.
        /// </summary>
        /// <param name="args"></param>
        private static int Main(string[] args)
        {
            #if DOTNETTOOL
            if (args.Length == 0)
            {
                Console.WriteLine($"NuGetDefense v{Version}");
                Console.WriteLine("-------------");
                Console.WriteLine($"{Environment.NewLine}Usage:");
                Console.WriteLine($"{Environment.NewLine}  nugetdefense projectFile.proj TargetFrameworkMoniker");
                Console.WriteLine($"{Environment.NewLine}  nugetdefense SolutionFile.sln Release");
                Console.WriteLine($"{Environment.NewLine}  nugetdefense SolutionFile.sln Debug|Any CPU");
                return 0;
            }
            #endif
            
            _settings = Settings.LoadSettings(Path.GetDirectoryName(args[0]));
            _projectFileName = Path.GetFileName(args[0]);
            ConfigureLogging();
            try
            {
                Log.Logger.Verbose("Logging Configured");

                Log.Logger.Verbose("Started NuGetDefense with arguments: {args}", args);
                var targetFramework = args.Length == 2 ? args[1] : "";

                if (args.Length > 2)
                {
                    
                }
                else if (args[0].EndsWith(".sln", StringComparison.OrdinalIgnoreCase))
                {
                    var specificFramework = !string.IsNullOrWhiteSpace(targetFramework);
                    if (specificFramework)
                    {
                        Log.Logger.Information("Target Framework: {framework}", targetFramework);
                    }

                    var solution = DotNetSolution.Load(args[0]);
                    var pkgs = new List<NuGetPackage>();
                    for (var i = 0; i < solution.Projects.Count; i++)
                    {
                        var project = solution.Projects[i];
                        var path = Path.Combine(Path.GetDirectoryName(args[0])!, project.Path
                            .Replace('\\', Path.DirectorySeparatorChar)
                            .Replace('/', Path.DirectorySeparatorChar));
                        
                        var proj = DotNetProject.Load(path);
                        if (!specificFramework && proj.Format == ProjectFormat.New)
                        {
                            var monikersListBuilder = new StringBuilder();
                            var monikers = proj.ProjectTargets.Select(t => t.Moniker).ToArray();
                            monikersListBuilder.Append(monikers[0]);
                            for (var index = 1; index < monikers.Length; index++)
                            {
                                monikersListBuilder.Append($", {monikers[index]}");
                            }

                            Log.Logger.Information("Target Frameworks for {project}: {frameworks}", project.Name, monikersListBuilder.ToString());
                            var nugetFile = new NuGetFile(path);
                            pkgs.AddDistinctPackages(monikers.SelectMany(m => nugetFile.LoadPackages(m, _settings.CheckTransitiveDependencies).Values));
                        }
                        else
                        {
                            pkgs.AddDistinctPackages(new NuGetFile(path).LoadPackages(targetFramework, _settings.CheckTransitiveDependencies).Values);
                        }
                    }

                    _pkgs = pkgs.ToArray();
                }
                else
                {
                    var nugetFile = new NuGetFile(args[0]);
                    _nuGetFile = nugetFile.Path;
                    Log.Logger.Verbose("NuGetFile Path: {nugetFilePath}", _nuGetFile);
                    
                    Log.Logger.Information("Target Framework: {framework}", string.IsNullOrWhiteSpace(targetFramework) ? "Undefined" : targetFramework);
                    Log.Logger.Verbose("Loading Packages");
                    Log.Logger.Verbose("Transitive Dependencies Included: {CheckTransitiveDependencies}", _settings.CheckTransitiveDependencies);
                    _pkgs = nugetFile.LoadPackages(targetFramework, _settings.CheckTransitiveDependencies).Values.ToArray();
                }
                
                var nonSensitivePackages = GetNonSensitivePackages(_pkgs);
                if (_settings.ErrorSettings.IgnoredPackages.Length > 0)
                    IgnorePackages(_pkgs, _settings.ErrorSettings.IgnoredPackages, out _pkgs);
                Log.Logger.Information("Loaded {packageCount} packages", _pkgs.Length);

                if (_settings.ErrorSettings.BlockedPackages.Length > 0) CheckBlockedPackages();
                if (_settings.ErrorSettings.AllowedPackages.Length > 0) CheckAllowedPackages();
                Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = null;
                if (_settings.OssIndex.Enabled)
                {
                    Log.Logger.Verbose("Checking with OSSIndex for Vulnerabilities");
                    vulnDict =
                        new Scanner(_nuGetFile, _settings.OssIndex.BreakIfCannotRun, UserAgentString, _settings.OssIndex.Username, _settings.OssIndex.ApiToken)
                            .GetVulnerabilitiesForPackages(nonSensitivePackages);
                }

                if (_settings.NVD.Enabled)
                {
                    Log.Logger.Verbose("Checking the embedded NVD source for Vulnerabilities");

                    vulnDict =
                        new NVD.Scanner(_nuGetFile, TimeSpan.FromSeconds(_settings.NVD.TimeoutInSeconds),
                                _settings.NVD.BreakIfCannotRun, _settings.NVD.SelfUpdate)
                            .GetVulnerabilitiesForPackages(_pkgs,
                                vulnDict);
                }

                Log.Logger.Information("ignoring {ignoredCVECount} Vulnerabilities", _settings.ErrorSettings.IgnoredCvEs.Length);
                if (_settings.ErrorSettings.IgnoredCvEs.Length > 0)
                    VulnerabilityData.IgnoreCVEs(vulnDict, _settings.ErrorSettings.IgnoredCvEs);

                ReportVulnerabilities(vulnDict);
                if (vulnDict?.Count == 0) return 0;
            }
            catch (Exception e)
            {
                var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error,
                    $"Encountered a fatal exception while checking for Dependencies in {_nuGetFile}. Exception: {e}");
                Console.WriteLine(msBuildMessage);
                Log.Logger.Fatal(msBuildMessage);
                return -1;
            }

            return 0;
        }

        private static void AddDistinctPackages(this List<NuGetPackage> pkgs,  IEnumerable<NuGetPackage> newPkgs)
        {
            foreach (var pkg in newPkgs)
            {
                if (pkgs.Any(p => p.Id == pkg.Id && p.Version == pkg.Version))
                {
                    pkgs.Add(pkg);
                }
            }
        }

        private static void ParseSolutionForProjects(string s)
        {
            // TODO: This will parse hte solution file into a list of projects relative to the solution file.
            throw new NotImplementedException();
        }

        /// <summary>
        /// Escapes all characters for Regex, then replaces '*' with '.*' (Regex wild Card for 0 or more of any character) 
        /// </summary>
        /// <param name="nuGetPackages"></param>
        /// <returns>a list of packages that do not match the wild card strings in SensitivePackages</returns>
        public static NuGetPackage[] GetNonSensitivePackages(NuGetPackage[] nuGetPackages)
        {
            var sensitiveRegexSet = _settings.SensitivePackages.Select(sp => Regex.Escape(sp).Replace(@"\*", ".*"));
            return nuGetPackages.Where(p => !sensitiveRegexSet.Any(x => Regex.IsMatch(p.Id, x))).ToArray();
        }

        private static void CheckAllowedPackages()
        {
            Log.Logger.Verbose("Checking Allowed Packages");

            foreach (var pkg in _pkgs.Where(p => !_settings.ErrorSettings.AllowedPackages.Any(b =>
                b.Id == p.Id && 
                (string.IsNullOrWhiteSpace(b.Version) || VersionRange.Parse(p.Version).Satisfies(new NuGetVersion(b.Version))))))
            {
                Log.Logger.Error("{packageName}:{version} was included in {nugetFile} but is not in the Allowed List", pkg.Id, pkg.Version, _nuGetFile);

                var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error, pkg.LineNumber, pkg.LinePosition,
                    $"{pkg.Id} is not listed as an allowed package and may not be used in this project");
                Console.WriteLine(msBuildMessage);
                Log.Logger.Error(msBuildMessage);
            }
        }

        private static void ReportVulnerabilities(Dictionary<string, Dictionary<string, Vulnerability>> vulnDict)
        {
            if (vulnDict == null)
            {
                Log.Logger.Information("No Vulnerabilities found in {numberOfPackages} packages", _pkgs.Length);
            }
            else
            {
                Log.Logger.Verbose("Building report of Vulnerabilities found in {numberOfPackages} packages", vulnDict.Keys.Count);
                var vulnReporter = new VulnerabilityReporter();
                vulnReporter.BuildVulnerabilityTextReport(vulnDict, _pkgs, _nuGetFile, _settings.WarnOnly,
                    _settings.ErrorSettings.Cvss3Threshold);
                if (_settings.VulnerabilityReports.OutputTextReport) Log.Logger.Information(vulnReporter.VulnerabilityTextReport);
                foreach (var msBuildMessage in vulnReporter.MsBuildMessages)
                {
                    Console.WriteLine(msBuildMessage);
                    Log.Logger.Debug(msBuildMessage);
                }


                if (string.IsNullOrWhiteSpace(_settings.VulnerabilityReports.JsonReportPath) && string.IsNullOrWhiteSpace(_settings.VulnerabilityReports.XmlReportPath)) return;

                vulnReporter.BuildVulnerabilityReport(vulnDict, _pkgs, _nuGetFile, _settings.WarnOnly,
                    _settings.ErrorSettings.Cvss3Threshold);
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
                var xmlser = new XmlTextWriter(File.Create(filename), Encoding.Default);
                var xser = new XmlSerializer(typeof(VulnerabilityReport));
                xser.Serialize(xmlser, vulnReporter.Report);
            }
        }

        private static void ConfigureLogging()
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
        }

        private static void CheckBlockedPackages()
        {
            foreach (var pkg in _pkgs)
            {
                Log.Logger.Verbose("Checking to see if {packageName}:{version} is Blocked", pkg.Id, pkg.Version);

                var blockedPackage = _settings.ErrorSettings.BlockedPackages.FirstOrDefault(b =>
                    b.Package.Id == pkg.Id && 
                    (string.IsNullOrWhiteSpace(b.Package.Version) || VersionRange.Parse(pkg.Version).Satisfies(new NuGetVersion(b.Package.Version))));
                if (blockedPackage == null)
                {
                    Log.Logger.Verbose("{packageName}:{version} is not Blocked", pkg.Id, pkg.Version);
                    continue;
                }
                
                var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error, pkg.LineNumber, pkg.LinePosition,
                    $"{pkg.Id}: {(string.IsNullOrEmpty(blockedPackage.CustomErrorMessage) ? "has been blocked and may not be used in this project" : blockedPackage.CustomErrorMessage)}");
                Console.WriteLine(msBuildMessage);
                Log.Logger.Error(msBuildMessage);
            }
        }
    }
}