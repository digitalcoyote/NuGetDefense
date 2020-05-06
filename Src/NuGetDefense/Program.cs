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

            _pkgs = LoadPackages(_nuGetFile);
            if (_settings.ErrorSettings.BlackListedPackages.Length > 0) CheckForBlacklistedPackages();
            if (_settings.ErrorSettings.WhiteListedPackages.Length > 0)
                foreach (var pkg in _pkgs.Where(p => !_settings.ErrorSettings.WhiteListedPackages.Any(b =>
                    b.Id == p.Id && VersionRange.Parse(p.Version).Satisfies(new NuGetVersion(b.Version)))))
                    Console.WriteLine(
                        $"{_nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : Error : {pkg.Id} has not been whitelisted and may not be used in this project");
            Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = null;
            if (_settings.OssIndex.Enabled)
                vulnDict =
                    new Scanner(_nuGetFile, _settings.OssIndex.BreakIfCannotRun).GetVulnerabilitiesForPackages(_pkgs);
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
        private static NuGetPackage[] IgnorePackages(IEnumerable<NuGetPackage> nuGetPackages)
        {
            return nuGetPackages.Where(nuget => !_settings.ErrorSettings.IgnoredPackages
                .Where(ignoredNupkg => ignoredNupkg.Id == nuget.Id)
                .Any(ignoredNupkg => !VersionRange.TryParse(ignoredNupkg.Version, out var versionRange) ||
                                     versionRange.Satisfies(new NuGetVersion(nuget.Version)))).ToArray();
        }

        /// <summary>
        ///     Loads NuGet packages in use form packages.config or PackageReferences in the project file
        /// </summary>
        /// <returns></returns>
        public static NuGetPackage[] LoadPackages(string packageSource)
        {
            IEnumerable<NuGetPackage> pkgs;
            if (Path.GetFileName(packageSource) == "packages.config")
                pkgs = XElement.Load(packageSource, LoadOptions.SetLineInfo).DescendantsAndSelf("package")
                    .Where(x => RemoveInvalidVersions(x))
                    .Select(x => new NuGetPackage
                    {
                        Id = (x.AttributeIgnoreCase("id")).Value, Version = x.AttributeIgnoreCase("version").Value,
                        LineNumber = ((IXmlLineInfo) x).LineNumber, LinePosition = ((IXmlLineInfo) x).LinePosition
                    });
            else
                pkgs = XElement.Load(packageSource, LoadOptions.SetLineInfo).DescendantsAndSelf("PackageReference")
                    .Where(x => RemoveInvalidVersions(x))
                    .Select(
                        x => new NuGetPackage
                        {
                            Id = x.AttributeIgnoreCase("Include").Value, Version = x.AttributeIgnoreCase("Version").Value,
                            LineNumber = ((IXmlLineInfo) x).LineNumber, LinePosition = ((IXmlLineInfo) x).LinePosition
                        });

            if (_settings.ErrorSettings.IgnoredPackages.Length > 0) pkgs = IgnorePackages(pkgs);

            return pkgs as NuGetPackage[] ?? pkgs.ToArray();
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