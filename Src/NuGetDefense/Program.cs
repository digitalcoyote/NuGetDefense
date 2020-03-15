using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using NuGet.Versioning;
using NuGetDefense.Configuration;
using NuGetDefense.Core;
using NuGetDefense.OSSIndex;
using NuGetDefense.PackageSources;
using PackagesConfigReader = NuGet.Packaging.PackagesConfigReader;

namespace NuGetDefense
{
    internal class Program
    {
        private static string _nuGetFile;
        private static NuGetPackage[] _pkgs;
        private static Settings _settings;

        /// <summary>
        ///     args[0] is expected to be the path to the project file.
        /// </summary>
        /// <param name="args"></param>
        private static void Main(string[] args)
        {
            _settings = Settings.LoadSettings(Path.GetDirectoryName(args[0]));
            var pkgConfig = Path.Combine(Path.GetDirectoryName(args[0]), "packages.config");
            _nuGetFile = File.Exists(pkgConfig) ? pkgConfig : args[0];

            string framework;
            if (args.Length > 1)
            {
                framework = args[1];
            }
            else
            {
                var targetFrameworkVersion = XElement.Load(File.OpenRead(args[0])).Descendants()
                    .First(x => x.Name.LocalName == "TargetFrameworkVersion").Value;

                framework = targetFrameworkVersion switch
                {
                    "v2.0" => "net20",
                    "v3.0" => "net30",
                    "v3.5" => "net35",
                    "v4.5" => "net45",
                    "v4.5.1" => "net451",
                    "v4.5.2" => "net452",
                    "v4.6" => "net46",
                    "v4.6.1" => "net461",
                    "v4.6.2" => "net462",
                    "v4.7" => "net27",
                    "v4.7.1" => "net471",
                    "v4.7.2" => "net472",
                    "v4.8" => "net48",
                    _ => "netstandard2.0"
                };
            }

            _pkgs = LoadPackages(_nuGetFile, framework);
            if (_settings.ErrorSettings.BlackListedPackages.Any())
                CheckForBlacklistedPackages();
            
            if (_settings.ErrorSettings.WhiteListedPackages.Any())
                foreach (var pkg in _pkgs.Where(p => !_settings.ErrorSettings.WhiteListedPackages.Any(b =>
                    b.Id == p.Id && VersionRange.Parse(p.Version).Satisfies(new NuGetVersion(b.Version)))))
                    Console.WriteLine(
                        $"{_nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : Error : {pkg.Id} has not been whitelisted and may not be used in this project");
            
            Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = null;
            
            if (_settings.OssIndex.Enabled)
                vulnDict = new Scanner(_nuGetFile, _settings.OssIndex.BreakIfCannotRun).GetVulnerabilitiesForPackages(_pkgs);
            
            if (_settings.NVD.Enabled)
                vulnDict = new NVD.Scanner(_nuGetFile, _settings.NVD.BreakIfCannotRun, _settings.NVD.SelfUpdate)
                                .GetVulnerabilitiesForPackages(_pkgs, vulnDict);
            
            if (_settings.ErrorSettings.IgnoredCvEs.Any())
                IgnoreCVEs(vulnDict);
            
            VulnerabilityReports.ReportVulnerabilities(vulnDict, _pkgs, 
                _nuGetFile, _settings.WarnOnly, _settings.ErrorSettings.CVSS3Threshold);
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
        private static IEnumerable<NuGetPackage> IgnorePackages(IEnumerable<NuGetPackage> nuGetPackages)
        {
            return nuGetPackages.Where(nuget => !_settings.ErrorSettings.IgnoredPackages
                .Where(ignoredNupkg => ignoredNupkg.Id == nuget.Id)
                .Any(ignoredNupkg => !VersionRange.TryParse(ignoredNupkg.Version, out var versionRange) ||
                                     versionRange.Satisfies(new NuGetVersion(nuget.Version))));
        }

        /// <summary>
        ///     Loads NuGet packages in use form packages.config or PackageReferences in the project file
        /// </summary>
        /// <returns></returns>
        public static NuGetPackage[] LoadPackages(string packageSource, string framework)
        {
            IEnumerable<NuGetPackage> nugetPackages;

            var packagesRead = PackagesConfigFileReader.TryReadFromFile(packageSource, out nugetPackages) ||
                                        ProjectFileReader.TryReadFromFile(packageSource, out nugetPackages);

            if (!packagesRead)
            {
                Console.WriteLine($"Warning : Could not read packages from source file '{packageSource}'");
                return (nugetPackages ?? Enumerable.Empty<NuGetPackage>()).ToArray();
            }
            
            if (_settings.ErrorSettings.IgnoredPackages.Any()) 
                nugetPackages = IgnorePackages(nugetPackages);
            
            try
            {
                nugetPackages = NuGetClient
                    .GetAllPackageDependencies(nugetPackages.Where(p => p.Id != "NuGetDefense").ToList(), framework)
                    .Result
                    .AsEnumerable();
            }
            catch (Exception e)
            {
                Console.WriteLine(
                    $"Warning : Error getting package dependencies from source '{packageSource}' : {e}");
            }

            return (nugetPackages ?? Enumerable.Empty<NuGetPackage>()).ToArray();
        }
    }
}