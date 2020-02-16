using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using MessagePack;
using Newtonsoft.Json.Linq;
using NuGet.Versioning;

namespace NVDFeedImporter
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var binName = "VulnerabilityData.bin";
            var nvdDict =
                new Dictionary<string, Dictionary<string, (string[] versions, string description, string cwe, string
                    vendor, double? score, AccessVectorType vector)>>();
            foreach (var link in GetJsonLinks())
            {
                Console.WriteLine(link);
                var fileName = link.Substring(link.LastIndexOf('/') + 1);
                fileName = fileName.Substring(0, fileName.LastIndexOf('.'));
                Console.WriteLine(link);
                using var feedDownloader = new WebClient();
                Stream jsonZippedDataStream = new MemoryStream(feedDownloader.DownloadData(link));
                var zipfile = new ZipArchive(jsonZippedDataStream);
                zipfile.Entries[0].ExtractToFile(fileName, true);
                var text = File.ReadAllText(fileName);
                var feed = JObject.Parse(text);


                foreach (var feedVuln in FeedVulnerabilities.FromJson(feed["CVE_Items"].ToString()))
                foreach (var match in feedVuln.Configurations.Nodes.Where(n => n.CpeMatch != null)
                    .SelectMany(n => n.CpeMatch))
                {
                    var cpe = Cpe.Parse(match.Cpe23Uri);
                    if (cpe.Part != "a") continue;
                    if (cpe.ProductVersion == "-")
                    {
                        NuGetVersion Start = null;
                        NuGetVersion End = null;
                        var includeStart = false;
                        var includeEnd = false;
                        if (!string.IsNullOrWhiteSpace(match.VersionStartIncluding))
                        {
                            Start = NuGetVersion.Parse(match.VersionStartIncluding);
                            includeStart = true;
                        }

                        if (!string.IsNullOrWhiteSpace(match.VersionEndIncluding))
                        {
                            End = NuGetVersion.Parse(match.VersionEndIncluding);
                            includeEnd = true;
                        }
                        else if (!string.IsNullOrWhiteSpace(match.VersionEndExcluding))
                        {
                            End = NuGetVersion.Parse(match.VersionEndExcluding);
                        }

                        var range = new VersionRange(Start, includeStart, End, includeEnd);

                        cpe.ProductVersion = string.IsNullOrWhiteSpace(range.ToString()) ? "*" : range.ToString();
                    }

                    Console.WriteLine($"CVE: {feedVuln.Cve.CveDataMeta.Id}");
                    Console.WriteLine($"Product: {cpe.ProductVersion}");
                    var cwe = "";
                    if (feedVuln.Cve.Problemtype.ProblemtypeData.Any())
                        if (feedVuln.Cve.Problemtype.ProblemtypeData[0].Description.Any())
                        {
                            cwe = feedVuln.Cve.Problemtype.ProblemtypeData[0].Description[0].Value;
                            Console.WriteLine(
                                $"CWE: {cwe}");
                        }

                    Console.WriteLine($"Product: {cpe.Product}");
                    var description = "";
                    if (feedVuln.Cve.Description.DescriptionData.Any())
                    {
                        Console.WriteLine(
                            $"Descritption: {feedVuln.Cve.Description.DescriptionData.First().Value}");
                        description = feedVuln.Cve.Description.DescriptionData.First().Value;
                    }

                    //TODO: Multiple Version Ranges need to be supported which means getting a more complicated range instead of replacing.

                    Console.WriteLine($"Vendor: {cpe.Vendor}");
                    Console.WriteLine(
                        $"CSVSS Score: {feedVuln.Impact.BaseMetricV3?.CvssV3?.BaseScore?.ToString() ?? ""}");
                    Console.WriteLine($"CSVSS Vector: {feedVuln.Impact.BaseMetricV3?.CvssV3?.AttackVector}");
                    if (!nvdDict.ContainsKey(cpe.Product))
                        nvdDict.Add(cpe.Product,
                            new Dictionary<string, (string[] versions, string description, string cwe, string vendor,
                                double? score, AccessVectorType vector)>());
                    if (!nvdDict[cpe.Product].ContainsKey(feedVuln.Cve.CveDataMeta.Id))
                    {
                        nvdDict[cpe.Product].Add(feedVuln.Cve.CveDataMeta.Id, (
                            new[] {cpe.ProductVersion}, description, cwe, cpe.Vendor, feedVuln.Impact.BaseMetricV3
                                ?.CvssV3
                                ?.BaseScore,
                            feedVuln.Impact.BaseMetricV3?.CvssV3?.AttackVector ?? AccessVectorType.UNSPECIFIED
                        ));
                    }
                    else
                    {
                        Console.WriteLine(
                            $"There is already an entry for {cpe.Product} with CVE: {feedVuln.Cve.CveDataMeta.Id}. Changing Version to: {cpe.ProductVersion}");

                        var vuln = nvdDict[cpe.Product][feedVuln.Cve.CveDataMeta.Id];
                        var versionList = vuln.versions.ToList();
                        if (versionList.Contains(cpe.ProductVersion)) continue;
                        versionList.Add(cpe.ProductVersion);
                        vuln.versions = versionList.ToArray();
                    }
                }
            }

            var lz4Options = MessagePackSerializerOptions.Standard.WithCompression(MessagePackCompression.Lz4BlockArray)
                .WithSecurity(MessagePackSecurity.UntrustedData);

            var dictBytes = MessagePackSerializer
                .Serialize(nvdDict, lz4Options);

            File.WriteAllBytes(binName, dictBytes);
        }

        private static void SaveToDB(JToken feedVulnerabilities)
        {
            // SQLiteConnection conn = new SQLiteConnection("Data Source=NuGetDefense.NVD.sqlite;Version=3;");
            // conn.Open();
        }

        private static IEnumerable<string> GetJsonLinks()
        {
            using var client = new WebClient();
            var feedsPage = client.DownloadString("https://nvd.nist.gov/vuln/data-feeds");

            // https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.zip
            var ls = Regex.Matches(feedsPage,
                @"https:\/\/nvd\.nist\.gov\/feeds\/json\/cve\/\d{0,4}\.?\d{0,4}\.?\/nvdcve-\d{0,4}\.?\d{0,4}\.?-\d{4}\.json\.zip",
                RegexOptions.Singleline).Select(m => m.ToString());
            return ls;
        }
    }
}