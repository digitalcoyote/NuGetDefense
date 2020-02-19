using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using NuGet.Versioning;
using NuGetDefense.OSSIndex;

namespace NuGetDefense
{
    internal class Program
    {
        internal static string nuGetFile;
        private static NuGetPackage[] pkgs;
        internal static Settings Settings;

        /// <summary>
        ///     args[0] is expected to be the path to the project file.
        /// </summary>
        /// <param name="args"></param>
        private static void Main(string[] args)
        {
            Settings = Settings.LoadSettings(Path.GetDirectoryName(args[0]));
            var pkgConfig = Path.Combine(Path.GetDirectoryName(args[0]), "packages.config");
            nuGetFile = File.Exists(pkgConfig) ? pkgConfig : args[0];
            pkgs = LoadPackages(nuGetFile, args[1]);
            if (Settings.ErrorSettings.IgnoredPackages.Length > 0) pkgs = IgnorePackages(pkgs);

            if (Settings.ErrorSettings.BlackListedPackages.Length > 0) CheckForBlacklistedPackages();
            if (Settings.ErrorSettings.WhiteListedPackages.Length > 0)
                foreach (var pkg in pkgs.Where(p => !Settings.ErrorSettings.WhiteListedPackages.Any(b =>
                    b.Id == p.Id && VersionRange.Parse(p.Version).Satisfies(new NuGetVersion(b.Version)))))
                    Console.WriteLine(
                        $"{nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : Error : {pkg.Id} has not been whitelisted and may not be used in this project");
            Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = null;
            if (Settings.OssIndex.Enabled) vulnDict = new Scanner().GetVulnerabilitiesForPackages(pkgs);
            if (Settings.NVD.Enabled) vulnDict = new NVD.Scanner().GetVulnerabilitiesForPackages(pkgs, vulnDict);
            if (Settings.ErrorSettings.IgnoredCvEs.Length > 0) IgnoreCVEs(vulnDict);
            ReportVulnerabilities(vulnDict);
        }

        private static void CheckForBlacklistedPackages()
        {
            foreach (var pkg in pkgs)
            {
                var blacklistedPackage = Settings.ErrorSettings.BlackListedPackages.FirstOrDefault(b =>
                    b.Package.Id == pkg.Id &&
                    VersionRange.Parse(pkg.Version).Satisfies(new NuGetVersion(b.Package.Version)));
                if(blacklistedPackage != null)
                    Console.WriteLine(
                        $"{nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : Error : {pkg.Id} : {(string.IsNullOrEmpty(blacklistedPackage.CustomErrorMessage) ? blacklistedPackage.CustomErrorMessage : "has been blacklisted and may not be used in this project")}");
            }
        }

        private static void IgnoreCVEs(Dictionary<string, Dictionary<string, Vulnerability>> vulnDict)
        {
            foreach (var vuln in vulnDict.Values)
            {
                foreach (var cve in Settings.ErrorSettings.IgnoredCvEs.Where(cve => vuln.Remove(cve)))
                {
                    Console.WriteLine($"Ignoring {cve}");
                }

                
            }
        }

        /// <summary>
/// Removes any Packages from the list before they are checked for Vulnerabilities
/// </summary>
/// <param name="nuGetPackages"> Array of Packages used as the source</param>
/// <returns>Filtered list of packages</returns>
        private static NuGetPackage[] IgnorePackages(NuGetPackage[] nuGetPackages)
        {
            return nuGetPackages.Where(nuget => !Settings.ErrorSettings.IgnoredPackages
                .Where(ignoredNupkg => ignoredNupkg.Id == nuget.Id)
                .Any(ignoredNupkg => !VersionRange.TryParse(ignoredNupkg.Version, out var versionRange) ||
                          versionRange.Satisfies(new NuGetVersion(nuget.Version)))).ToArray();
        }

        private static void ReportVulnerabilities(Dictionary<string, Dictionary<string, Vulnerability>> vulnDict)
        {
            foreach (var pkg in pkgs.Where(p => p.LineNumber != null && vulnDict.ContainsKey(p.Id)))
            {
                var vulnerabilities = vulnDict[pkg.Id];

                Console.WriteLine("*************************************");
                //Plan to use Warning: for warnings later
                //Plan to combine messages into a single Console.Write.
                bool warnOnly = Settings.WarnOnly || !vulnerabilities.Any(v => v.Value.CvssScore >= Settings.ErrorSettings.CVSS3Threshold);
                var dependantVulnerabilities = pkg.Dependencies.Where(dep => vulnDict.ContainsKey(dep));
                Console.WriteLine(
                    $"{nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : {(warnOnly ? "Warning" : "Error")} : {vulnerabilities.Count} vulnerabilities found for {pkg.Id} @ {pkg.Version}");
                Console.WriteLine(
                    $"{nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : {(warnOnly  ? "Warning" : "Error")} : {dependantVulnerabilities.Count()} vulnerabilities found for dependencies of {pkg.Id} @ {pkg.Version}");

                foreach (var cve in vulnerabilities.Keys)
                {
                    warnOnly = Settings.WarnOnly ||
                                    vulnerabilities[cve].CvssScore <= Settings.ErrorSettings.CVSS3Threshold;
                    Console.WriteLine(
                        $"{nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : {(warnOnly ? "Warning" : "Error")} : {cve}: {vulnerabilities[cve].Description}");
                    Console.WriteLine($"Description: {vulnerabilities[cve].Description}");
                    Console.WriteLine($"CVE: {cve}");
                    Console.WriteLine($"CWE: {vulnerabilities[cve].Cwe}");
                    Console.WriteLine($"CVSS Score: {vulnerabilities[cve].CvssScore}");
                    Console.WriteLine($"CVSS Vector: {vulnerabilities[cve].Vector}");
                    // if (vulnerabilities[cve].Version?.Length > 0)
                    //     Console.WriteLine($"Affected Version: {vulnerabilities[cve].Version}");
                    Console.WriteLine("---------------------------");
                }

                foreach (var dependancy in dependantVulnerabilities)
                {
                    vulnerabilities = vulnDict[dependancy];
                    foreach (var cve in vulnerabilities.Keys)
                    {
                        warnOnly = Settings.WarnOnly ||
                                        vulnerabilities[cve].CvssScore <= Settings.ErrorSettings.CVSS3Threshold;
                        Console.WriteLine(
                            $"{nuGetFile}({pkg.LineNumber},{pkg.LinePosition}) : {(warnOnly ? "Warning" : "Error")} : {cve}: {dependancy}: {vulnerabilities[cve].Description}");
                        Console.WriteLine($"Description: {vulnerabilities[cve].Description}");
                        Console.WriteLine($"CVE: {cve}");
                        Console.WriteLine($"CWE: {vulnerabilities[cve].Cwe}");
                        Console.WriteLine($"CVSS Score: {vulnerabilities[cve].CvssScore}");
                        Console.WriteLine($"CVSS Vector: {vulnerabilities[cve].Vector}");
                        // if (vulnerabilities[cve].Version?.Length > 0)
                        //     Console.WriteLine($"Affected Version: {vulnerabilities[cve].Version}");
                        Console.WriteLine("---------------------------");
                    }
                }
            }
        }


        /// <summary>
        ///     Loads NuGet packages in use form packages.config or PackageReferences in the project file
        /// </summary>
        /// <returns></returns>
        public static NuGetPackage[] LoadPackages(string packageSource, string framework)
        {
            IEnumerable<NuGetPackage> pkgs;
            if (Path.GetFileName(packageSource) == "packages.config")
                pkgs = XElement.Load(packageSource, LoadOptions.SetLineInfo).DescendantsAndSelf("package").Select(x =>
                    new NuGetPackage
                    {
                        Id = x.Attribute("id").Value, Version = x.Attribute("version").Value,
                        LineNumber = ((IXmlLineInfo) x).LineNumber, LinePosition = ((IXmlLineInfo) x).LinePosition
                    });
            else
                pkgs = XElement.Load(packageSource, LoadOptions.SetLineInfo).DescendantsAndSelf("PackageReference")
                    .Select(
                        x => new NuGetPackage
                        {
                            Id = x.Attribute("Include").Value, Version = x.Attribute("Version").Value,
                            LineNumber = ((IXmlLineInfo) x).LineNumber, LinePosition = ((IXmlLineInfo) x).LinePosition
                        });

            return NuGetClient.GetAllPackageDependencies(pkgs.Where(p => p.Id != "NuGetDefense").ToList(), framework)
                .Result.ToArray();
        }
    }
}