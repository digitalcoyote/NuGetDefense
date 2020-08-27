using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
            @"NuGetDefense/1.0.8.0-beta (https://github.com/digitalcoyote/NuGetDefense/blob/master/README.md)";

        private static string _nuGetFile;
        private static NuGetPackage[] _pkgs;
        private static Settings _settings;

        /// <summary>
        ///     args[0] is expected to be the path to the project file.
        /// </summary>
        /// <param name="args"></param>
        private static void Main(string[] args)
        {
            var nugetFile = new NuGetFile(args[0]);
            _nuGetFile = nugetFile.Path;
            _settings = Settings.LoadSettings(Path.GetDirectoryName(args[0]));
            ConfigureLogging(Path.GetFileName(args[0]));
            var targetFramework = args.Length > 1 ? args[1] : "";
            _pkgs = nugetFile.LoadPackages(targetFramework, _settings.CheckTransitiveDependencies).Values.ToArray();
            if (_settings.ErrorSettings.BlockedPackages.Length > 0) CheckBlockedPackages();
            if (_settings.ErrorSettings.AllowedPackages.Length > 0) CheckAllowedPackages();
            Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = null;
            if (_settings.OssIndex.Enabled)
                vulnDict =
                    new Scanner(_nuGetFile, _settings.OssIndex.BreakIfCannotRun, UserAgentString)
                        .GetVulnerabilitiesForPackages(_pkgs);
            if (_settings.NVD.Enabled)
                vulnDict =
                    new NVD.Scanner(_nuGetFile, TimeSpan.FromSeconds(_settings.NVD.TimeoutInSeconds),
                            _settings.NVD.BreakIfCannotRun, _settings.NVD.SelfUpdate)
                        .GetVulnerabilitiesForPackages(_pkgs,
                            vulnDict);
            if (_settings.ErrorSettings.IgnoredCvEs.Length > 0)
                VulnerabilityData.IgnoreCVEs(vulnDict, _settings.ErrorSettings.IgnoredCvEs);
            if (vulnDict == null) Log.Logger.Information("No Vulnerabilities found in {0} packages", _pkgs.Length);

            ReportVulnerabilities(vulnDict);
        }

        private static void CheckAllowedPackages()
        {
            foreach (var pkg in _pkgs.Where(p => !_settings.ErrorSettings.AllowedPackages.Any(b =>
                b.Id == p.Id && VersionRange.Parse(p.Version).Satisfies(new NuGetVersion(b.Version)))))
            {
                var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error, pkg.LineNumber, pkg.LinePosition,
                    $"{pkg.Id} is not listed as an allowed package and may not be used in this project");
                Console.WriteLine(msBuildMessage);
                Log.Logger.Debug(msBuildMessage);
            }
        }

        private static void ReportVulnerabilities(Dictionary<string, Dictionary<string, Vulnerability>> vulnDict)
        {
            var vulnReporter = new VulnerabilityReporter();
            vulnReporter.BuildVulnerabilityReport(vulnDict, _pkgs, _nuGetFile, _settings.WarnOnly,
                _settings.ErrorSettings.Cvss3Threshold);
            Log.Logger.Error(vulnReporter.VulnerabilityReport);
            foreach (var msBuildMessage in vulnReporter.MsBuildMessages)
            {
                Console.WriteLine(msBuildMessage);
                Log.Logger.Debug(msBuildMessage);
            }
        }

        private static void ConfigureLogging(string projectFileName)
        {
            if (!(_settings.Logs?.Length > 0)) return;
            var loggerConfiguration = new LoggerConfiguration();
            foreach (var log in _settings.Logs)
                loggerConfiguration.WriteTo.File(log.OutPut.Replace("{project}", projectFileName),
                    log.LogLevel,
                    rollingInterval: log.RollingInterval);
            loggerConfiguration.WriteTo.Console();
            Log.Logger = loggerConfiguration.CreateLogger();
        }

        private static void CheckBlockedPackages()
        {
            foreach (var pkg in _pkgs)
            {
                var blockedPackage = _settings.ErrorSettings.BlockedPackages.FirstOrDefault(b =>
                    b.Package.Id == pkg.Id &&
                    VersionRange.Parse(pkg.Version).Satisfies(new NuGetVersion(b.Package.Version)));
                if (blockedPackage == null) continue;

                var msBuildMessage = MsBuild.Log(_nuGetFile, MsBuild.Category.Error, pkg.LineNumber, pkg.LinePosition,
                    $"{pkg.Id}: {(string.IsNullOrEmpty(blockedPackage.CustomErrorMessage) ? blockedPackage.CustomErrorMessage : "has been blocked and may not be used in this project")}");
                Log.Logger.Debug(msBuildMessage);
            }
        }
    }
}