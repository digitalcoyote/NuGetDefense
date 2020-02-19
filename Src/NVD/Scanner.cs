using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using MessagePack;
using NuGet.Versioning;

namespace NuGetDefense.NVD
{
    public class Scanner
    {
        public enum AccessVectorType
        {
            LOCAL,
            NETWORK,
            ADJACENT_NETWORK,
            PHYSICAL,
            UNSPECIFIED
        }

        private readonly Dictionary<string, Dictionary<string, (string[] versions, string description, string cwe,
            string vendor, double? score, AccessVectorType vector)>> nvdDict;

        public Scanner()
        {
            var lz4Options = MessagePackSerializerOptions.Standard.WithCompression(MessagePackCompression.Lz4BlockArray)
                .WithSecurity(MessagePackSecurity.UntrustedData);
            var vulnDataFile = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location),
                "VulnerabilityData.bin");

            var nvdData = File.Open(vulnDataFile, FileMode.Open, FileAccess.Read);
            nvdDict = MessagePackSerializer
                .Deserialize<
                    Dictionary<string, Dictionary<string, (string[] versions, string description, string cwe, string
                        vendor
                        , double? score, AccessVectorType vector)>>>(nvdData, lz4Options);
        }

        public Dictionary<string, Dictionary<string, Vulnerability>> GetVulnerabilitiesForPackages(NuGetPackage[] pkgs,
            Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = null)
        {
            try
            {
                if (vulnDict == null) vulnDict = new Dictionary<string, Dictionary<string, Vulnerability>>();
                foreach (var pkg in pkgs)
                {
                    var pkgId = pkg.Id.ToLower();
                    if (!nvdDict.ContainsKey(pkgId)) continue;
                    if (!vulnDict.ContainsKey(pkgId)) vulnDict.Add(pkgId, new Dictionary<string, Vulnerability>());
                    foreach (var cve in nvdDict[pkgId].Keys.Where(cve => nvdDict[pkgId][cve].versions.Any(v =>
                        VersionRange.Parse(v).Satisfies(new NuGetVersion(pkg.Version)))))
                        vulnDict[pkgId].Add(cve, new Vulnerability(cve, nvdDict[pkgId][cve]));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(
                    $"{Program.nuGetFile} : {(Program.Settings.NVD.BreakIfCannotRun ? "Error" : "Warning")} : NuGetDefense : NVD scan failed with exception: {e}");
            }

            return vulnDict;
        }
    }
}