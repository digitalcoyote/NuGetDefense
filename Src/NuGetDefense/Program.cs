using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Linq;
using NuGet.Versioning;
using NuGetDefense.Configuration;
using NuGetDefense.Core;
using NuGetDefense.OSSIndex;

namespace NuGetDefense
{
    internal class Program
    {
        private static string _nuGetFile;
        private const string UserAgentString = @"NuGetDefense/1.0.8.0-beta (https://github.com/digitalcoyote/NuGetDefense/blob/master/README.md)";
        private static NuGetPackage[] _pkgs;
        private static Settings _settings;

        /// <summary>
        ///     args[0] is expected to be the path to the project file.
        /// </summary>
        /// <param name="args"></param>
        private static void Main(string[] args)
        {
            _settings = Settings.LoadSettings(Path.GetDirectoryName(args[0]));
            _pkgs = LoadPackages(args[0], _settings.CheckTransitiveDependencies).Values.ToArray();
            if (_settings.ErrorSettings.BlackListedPackages.Length > 0) CheckForBlacklistedPackages();
            if (_settings.ErrorSettings.WhiteListedPackages.Length > 0)
                foreach (var pkg in _pkgs.Where(p => !_settings.ErrorSettings.WhiteListedPackages.Any(b =>
                    b.Id == p.Id && VersionRange.Parse(p.Version).Satisfies(new NuGetVersion(b.Version)))))
                    Console.WriteLine(
                        $"{_nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : Error : {pkg.Id} has not been whitelisted and may not be used in this project");
            Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = null;
            if (_settings.OssIndex.Enabled)
                vulnDict =
                    new Scanner(_nuGetFile, _settings.OssIndex.BreakIfCannotRun, UserAgentString).GetVulnerabilitiesForPackages(_pkgs);
            if (_settings.NVD.Enabled)
                vulnDict =
                    new NVD.Scanner(_nuGetFile, TimeSpan.FromSeconds(_settings.NVD.TimeoutInSeconds),
                            _settings.NVD.BreakIfCannotRun, _settings.NVD.SelfUpdate)
                        .GetVulnerabilitiesForPackages(_pkgs,
                            vulnDict);
            if (_settings.ErrorSettings.IgnoredCvEs.Length > 0) IgnoreCVEs(vulnDict);
            if (vulnDict != null)
                VulnerabilityReports.ReportVulnerabilities(vulnDict, _pkgs, _nuGetFile, _settings.WarnOnly,
                    _settings.ErrorSettings.CVSS3Threshold);
        }

        private static void CheckForBlacklistedPackages()
        {
            foreach (var pkg in _pkgs)
            {
                var blacklistedPackage = _settings.ErrorSettings.BlackListedPackages.FirstOrDefault(b =>
                    b.Package.Id == pkg.Id &&
                    VersionRange.Parse(pkg.Version).Satisfies(new NuGetVersion(b.Package.Version)));
                if (blacklistedPackage != null)
                    Console.WriteLine(
                        $"{_nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : Error : {pkg.Id} : {(string.IsNullOrEmpty(blacklistedPackage.CustomErrorMessage) ? blacklistedPackage.CustomErrorMessage : "has been blacklisted and may not be used in this project")}");
            }
        }

        /// <summary>
        /// Removes CVE's from the vulnerablity reports if they ar ein the ignoredCVEs list
        /// </summary>
        /// <param name="vulnDict"></param>
        private static void IgnoreCVEs(Dictionary<string, Dictionary<string, Vulnerability>> vulnDict)
        {
            foreach (var vuln in vulnDict.Values)
            foreach (var cve in _settings.ErrorSettings.IgnoredCvEs.Where(cve => vuln.Remove(cve)))
                Console.WriteLine($"Ignoring {cve}");
        }

        /// <summary>
        ///     Removes any Packages from the list before they are checked for Vulnerabilities
        /// </summary>
        /// <param name="nuGetPackages"> Array of Packages used as the source</param>
        /// <returns>Filtered list of packages</returns>
        private static Dictionary<string, NuGetPackage> IgnorePackages(Dictionary<string, NuGetPackage> nuGetPackages)
        {
            return (Dictionary<string, NuGetPackage>) nuGetPackages.Where(nuget => !_settings.ErrorSettings.IgnoredPackages
                .Where(ignoredNupkg => ignoredNupkg.Id == nuget.Value.Id)
                .Any(ignoredNupkg => !VersionRange.TryParse(ignoredNupkg.Version, out var versionRange) ||
                                     versionRange.Satisfies(new NuGetVersion(nuget.Value.Version))))
                .ToDictionary(kv => kv.Key, kv => kv.Value);
        }

        /// <summary>
        ///     Loads NuGet packages in use form packages.config or PackageReferences in the project file
        /// </summary>
        /// <returns></returns>
        public static Dictionary<string, NuGetPackage> LoadPackages(string projectFile, bool checkTransitiveDependencies = true)
        {
            var pkgConfig = Path.Combine(Path.GetDirectoryName(projectFile), "packages.config");
            var legacy = File.Exists(pkgConfig);
            _nuGetFile = legacy ? pkgConfig : projectFile;
            Dictionary<string, NuGetPackage> pkgs = new Dictionary<string, NuGetPackage>();

                if (Path.GetFileName(projectFile) == "packages.config")
                    pkgs = XElement.Load(projectFile, LoadOptions.SetLineInfo).DescendantsAndSelf("package")
                        .Where(x => RemoveInvalidVersions(x))
                        .Select(x => new NuGetPackage
                        {
                            Id = (x.AttributeIgnoreCase("id")).Value, Version = x.AttributeIgnoreCase("version").Value,
                            LineNumber = ((IXmlLineInfo) x).LineNumber, LinePosition = ((IXmlLineInfo) x).LinePosition
                        }).ToDictionary(p => p.Id);
                else
                    pkgs = XElement.Load(projectFile, LoadOptions.SetLineInfo).DescendantsAndSelf("PackageReference")
                        .Where(x => RemoveInvalidVersions(x))
                        .Select(
                            x => new NuGetPackage
                            {
                                Id = x.AttributeIgnoreCase("Include").Value,
                                Version = x.AttributeIgnoreCase("Version").Value,
                                LineNumber = ((IXmlLineInfo) x).LineNumber,
                                LinePosition = ((IXmlLineInfo) x).LinePosition
                            }).ToDictionary(p => p.Id);;
                if(!legacy)
                {
                    var resolvedPackages = dotnetListPackages(projectFile);

                    if (checkTransitiveDependencies)
                    {
                        foreach (var (key, value) in pkgs.Where(package => resolvedPackages.ContainsKey(package.Key)))
                        {
                            resolvedPackages[key].LineNumber = value.LineNumber;
                            resolvedPackages[key].LinePosition = value.LinePosition;
                        }

                        pkgs = resolvedPackages;
                    }
                    else
                    {
                        foreach (var (key, _) in pkgs)
                        {
                            pkgs[key].Version = resolvedPackages[key].Version;
                        }
                    }
                }
                else if (checkTransitiveDependencies)
                {
                    Console.WriteLine(
                        $"{_nuGetFile} : Warning : Transitive depency checking skipped. 'dotnet list package --include-transitive' only supports SDK style NuGet Package References");
                }
                
                if (_settings.ErrorSettings.IgnoredPackages.Length > 0) pkgs = IgnorePackages(pkgs);

            return pkgs;
        }

        /// <summary>
        /// Uses 'dotnet list' to get a list of resolved versions and dependencies
        /// </summary>
        /// <param name="projectFile"></param>
        /// <returns></returns>
        private static Dictionary<string, NuGetPackage> dotnetListPackages(string projectFile)
        {
            Dictionary<string, NuGetPackage> pkgs;
            var startInfo = new ProcessStartInfo("dotnet")
            {
                Arguments = $"list {projectFile} package --include-transitive",
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            var dotnet = new Process() {StartInfo = startInfo};
            dotnet.Start();
            dotnet.WaitForExit();
            var output = dotnet.StandardOutput.ReadToEnd();

            var lines = output.Split(Environment.NewLine);
            var topLevelPackageResolvedIndex = lines[2].IndexOf("Resolved") - 8;
            var transitiveHeaderIndex = Array.FindIndex(lines, l => l.Contains("Transitive Package"));
            pkgs = lines.Skip(3).Take(transitiveHeaderIndex - 4).Select(l => new NuGetPackage
            {
                Id = l.Substring(l.IndexOf(">") + 2, topLevelPackageResolvedIndex - l.IndexOf(">") + 3).Trim(),
                Version = l.Substring(topLevelPackageResolvedIndex).Trim()
            }).ToDictionary(p => p.Id);;
                
            var transitiveResolvedColumnStart = output.Split(Environment.NewLine)[transitiveHeaderIndex].IndexOf("Resolved") - 8;

            pkgs.Concat(lines.Skip(transitiveHeaderIndex + 1).SkipLast(2).Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(l => new NuGetPackage
                {
                    Id = l.Substring(l.IndexOf(">") + 2, transitiveResolvedColumnStart - l.IndexOf(">") + 3).Trim(),
                    Version = l.Substring(transitiveResolvedColumnStart).Trim()
                }).ToDictionary(p => p.Id));

            return pkgs;
        }

        private static bool RemoveInvalidVersions(XElement x)
        {
            if (NuGetVersion.TryParse(x.AttributeIgnoreCase("Version")?.Value, out var version)) return true;
            if (version != null)
            {
                Console.WriteLine(
                    $"{_nuGetFile}({((IXmlLineInfo) x).LineNumber},{((IXmlLineInfo) x).LinePosition}) : Warning : {version} is not a valid NuGetVersion and is being ignored. See 'https://docs.microsoft.com/en-us/nuget/concepts/package-versioning' for more info on valid versions");
            }
            else
            {
                Console.WriteLine(
                        $"{_nuGetFile}({((IXmlLineInfo) x).LineNumber},{((IXmlLineInfo) x).LinePosition}) : Warning : Unable to find a version for this package. It will be ignored.");
            }
            return false;
        }
    }
}