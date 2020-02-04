using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using NuGetDefense.OSSIndex;

namespace NuGetDefense
{
    class Program
    {
        /// <summary>
        /// args[0] is expected to be the path to the project file.
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            var exitCode = 0;
            var pkgConfig = Path.Combine(Path.GetDirectoryName(args[0]), "packages.config");
            var pkgs = LoadPackages(File.Exists(pkgConfig) ? pkgConfig : args[0]);

            var reports = OSSIndex.RestApi.GetVulnerabilitiesForPackages(pkgs).ToArray();
            foreach (var report in reports)
            {
                var StdErrWriter = Console.Error;
                var pkg = pkgs.First(p => p.PackageUrl == report.Coordinates);
                Console.WriteLine("*************************************");
                //Plan to use Warning: for warnings later
                //Plan to combine messages into a single Console.Write.
                StdErrWriter.WriteLine($"{args[0]}({pkg.LineNumber},{pkg.LinePosition}) : Error : Vulnerabilities found for {pkg.Id} @ {pkg.Version}");
                Console.WriteLine($"Description: {report.Description}");
                Console.WriteLine($"Reference: {report.Reference}");
                foreach (var vulnerability in report.Vulnerabilities)
                {
                    exitCode++;
                    Console.WriteLine($"Title: {vulnerability.Title}");
                    Console.WriteLine($"Description: {vulnerability.Description}");
                    Console.WriteLine($"Id: {vulnerability.Id}");
                    Console.WriteLine($"CVE: {vulnerability.Cve}");
                    Console.WriteLine($"CWE: {vulnerability.Cwe}");
                    Console.WriteLine($"CVSS Score: {vulnerability.CvssScore.ToString(CultureInfo.InvariantCulture)}");
                    Console.WriteLine($"CVSS Vector: {vulnerability.CvssVector}");
                    if(vulnerability.VersionRanges?.Length > 0)Console.Error.WriteLine($"Affected Versions: {vulnerability.VersionRanges}");
                    Console.WriteLine("---------------------------");
                }
            }
        }
        
        
        /// <summary>
        /// Loads NuGet packages in use form packages.config or PackageReferences in the project file
        /// </summary>
        /// <returns></returns>
        public static NuGetPackage[] LoadPackages(string packageSource)
        {
            if(Path.GetFileName(packageSource) == "packages.config")
            {
                return XElement.Load(packageSource, LoadOptions.SetLineInfo).DescendantsAndSelf("package").Select(x => new NuGetPackage()
                    {Id = x.Attribute("id").Value, Version = x.Attribute("version").Value, LineNumber = ((IXmlLineInfo)x).LineNumber, LinePosition = ((IXmlLineInfo)x).LinePosition}).ToArray();
            }

            return XElement.Load(packageSource, LoadOptions.SetLineInfo).DescendantsAndSelf("PackageReference").Select(x => new NuGetPackage()
                {Id = x.Attribute("Include").Value, Version = x.Attribute("Version").Value, LineNumber = ((IXmlLineInfo)x).LineNumber, LinePosition = ((IXmlLineInfo)x).LinePosition}).ToArray();
        }
    }
}