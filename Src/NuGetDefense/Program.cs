using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Serialization;
using NuGet.Versioning;
using NuGetDefense.Configuration;
using NuGetDefense.Core;
using NuGetDefense.OSSIndex;
using Serilog;

namespace NuGetDefense
{
    internal class Program
    {
        private const string UserAgentString =
            @"NuGetDefense/1.0.10.0-pre0001 (https://github.com/digitalcoyote/NuGetDefense/blob/master/README.md)";

        private static string _nuGetFile;
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
                var versionString = Assembly.GetEntryAssembly()
                    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                    ?.InformationalVersion;
                Console.WriteLine($"NuGetDefense v{versionString}");
                Console.WriteLine("-------------");
                Console.WriteLine("\nUsage:");
                Console.WriteLine("  nugetdefense projectFile.proj TargetFrameworkMoniker");
                return 0;
            }
#endif
            _settings = Settings.LoadSettings(Path.GetDirectoryName(args[0]));
            ConfigureLogging(Path.GetFileName(args[0]));
            try
            {
                Log.Logger.Verbose("Logging Configured");

                Log.Logger.Verbose("Started NuGetDefense with arguments: {args}", args);
                var nugetFile = new NuGetFile(args[0]);
                _nuGetFile = nugetFile.Path;
                Log.Logger.Verbose("NuGetFile Path: {nugetFilePath}", _nuGetFile);


                var targetFramework = args.Length > 1 ? args[1] : "";
                Log.Logger.Information("Target Framework: {framework}", string.IsNullOrWhiteSpace(targetFramework) ? "Undefined" : targetFramework);
                Log.Logger.Verbose("Loading Packages");
                Log.Logger.Verbose("Transitive Dependencies Included: {CheckTransitiveDependencies}", _settings.CheckTransitiveDependencies);
                _pkgs = nugetFile.LoadPackages(targetFramework, _settings.CheckTransitiveDependencies).Values.ToArray();
                var nonSensitivePackages = _pkgs.Where(p => !_settings.SensitivePackages.Contains(p.Id)).ToArray();
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

        private static void CheckAllowedPackages()
        {
            Log.Logger.Verbose("Checking Allowed Packages");

            foreach (var pkg in _pkgs.Where(p => !_settings.ErrorSettings.AllowedPackages.Any(b =>
                b.Id == p.Id && VersionRange.Parse(p.Version).Satisfies(new NuGetVersion(b.Version)))))
            {
                Log.Logger.Error("{packageName}:{version} was included in {nugetFile} but is not in the Allowed List", pkg.Id, pkg.Version, _nuGetFile);

                var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error, pkg.LineNumber, pkg.LinePosition,
                    $"{pkg.Id} is not listed as an allowed package and may not be used in this project");
                Console.WriteLine(msBuildMessage);
                Log.Logger.Debug(msBuildMessage);
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

                var fileTimestamp = DateTime.Now.ToString("u");

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
                    File.WriteAllText(Path.Combine(_settings.VulnerabilityReports.JsonReportPath, $"VulnerabilityReport-{fileTimestamp}.json"), contents
                    );
                }

                if (string.IsNullOrWhiteSpace(_settings.VulnerabilityReports.XmlReportPath)) return;
                
                var xmlser = new XmlTextWriter(Path.Combine(_settings.VulnerabilityReports.JsonReportPath, $"VulnerabilityReport-{fileTimestamp}.xml"), Encoding.Default);
                var xser = new XmlSerializer(typeof(VulnerabilityReport));
                xser.Serialize(xmlser, vulnReporter.Report);
            }
        }

        private static void ConfigureLogging(string projectFileName)
        {
            if (!(_settings.Logs?.Length > 0)) return;
            var loggerConfiguration = new LoggerConfiguration();
            foreach (var log in _settings.Logs)
            {
                var file = log.OutPut.Replace("{project}", projectFileName);
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
                    VersionRange.Parse(pkg.Version).Satisfies(new NuGetVersion(b.Package.Version)));
                if (blockedPackage == null)
                {
                    Log.Logger.Verbose("{packageName}:{version} is not Blocked", pkg.Id, pkg.Version);
                    continue;
                }

                Log.Logger.Error("{packageName}:{version} is Blocked but was included in {nugetFile}", pkg.Id, pkg.Version, _nuGetFile);

                var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error, pkg.LineNumber, pkg.LinePosition,
                    $"{pkg.Id}: {(string.IsNullOrEmpty(blockedPackage.CustomErrorMessage) ? blockedPackage.CustomErrorMessage : "has been blocked and may not be used in this project")}");
                Log.Logger.Debug(msBuildMessage);
            }
        }
    }
}