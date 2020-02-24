using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using NuGet.Versioning;
using NuGetDefense.Core;
using NVDFeedImporter;

namespace NuGetDefense.NVD
{
    public class FeedUpdater
    {
        public static void AddFeedToVulnerabilityData(NVDFeed feed,
            Dictionary<string, Dictionary<string, VulnerabilityEntry>> nvdDict)
        {
            foreach (var feedVuln in feed.CveItems)
            foreach (var match in feedVuln.Configurations.Nodes.Where(n => n.CpeMatch != null)
                .SelectMany(n => n.CpeMatch))
            {
                var cpe = Cpe.Parse(match.Cpe23Uri);
                if (cpe.Part != "a") continue;
                if (cpe.ProductVersion == "-")
                {
                    NuGetVersion start = null;
                    NuGetVersion end = null;
                    var includeStart = false;
                    var includeEnd = false;
                    if (!string.IsNullOrWhiteSpace(match.VersionStartIncluding))
                    {
                        start = NuGetVersion.Parse(match.VersionStartIncluding);
                        includeStart = true;
                    }

                    if (!string.IsNullOrWhiteSpace(match.VersionEndIncluding))
                    {
                        end = NuGetVersion.Parse(match.VersionEndIncluding);
                        includeEnd = true;
                    }
                    else if (!string.IsNullOrWhiteSpace(match.VersionEndExcluding))
                    {
                        end = NuGetVersion.Parse(match.VersionEndExcluding);
                    }

                    var range = new VersionRange(start, includeStart, end, includeEnd);

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
                        new Dictionary<string, VulnerabilityEntry>());
                if (!nvdDict[cpe.Product].ContainsKey(feedVuln.Cve.CveDataMeta.Id))
                {
                    var specifiedVector = Enum.TryParse<Vulnerability.AccessVectorType>(
                        feedVuln.Impact.BaseMetricV3?.CvssV3?.AttackVector, out var vector);
                    nvdDict[cpe.Product].Add(feedVuln.Cve.CveDataMeta.Id, new VulnerabilityEntry
                        {
                            Versions = new[] {cpe.ProductVersion},
                            Description = description,
                            Cwe = cwe,
                            Vendor = cpe.Vendor,
                            Score = feedVuln.Impact.BaseMetricV3?.CvssV3?.BaseScore,
                            Vector = specifiedVector ? vector : Vulnerability.AccessVectorType.UNSPECIFIED,
                            References = feedVuln.Cve.References.ReferenceData.Select(r => r.Url.ToString()).ToArray()
                        }
                    );
                }
                else
                {
                    Console.WriteLine(
                        $"There is already an entry for {cpe.Product} with CVE: {feedVuln.Cve.CveDataMeta.Id}. Changing Version to: {cpe.ProductVersion}");

                    var vuln = nvdDict[cpe.Product][feedVuln.Cve.CveDataMeta.Id];
                    var versionList = vuln.Versions.ToList();
                    if (versionList.Contains(cpe.ProductVersion)) continue;
                    versionList.Add(cpe.ProductVersion);
                    vuln.Versions = versionList.ToArray();
                }
            }
        }

        public static IEnumerable<string> GetJsonLinks(bool AllLinks = false)
        {
            using var client = new WebClient();
            var pattern = !AllLinks ? @"https:\/\/nvd\.nist\.gov\/feeds\/json\/cve\/\d{0,4}\.?\d{0,4}\.?\/nvdcve-\d{0,4}\.?\d{0,4}\.?-\d{4}\.json\.zip" : @"https:\/\/nvd\.nist\.gov\/feeds\/json\/cve\/\d{0,4}\.?\d{0,4}\.?\/nvdcve-.*\.json\.zip";

            var feedsPage = client.DownloadString("https://nvd.nist.gov/vuln/data-feeds");
            var ls = Regex.Matches(feedsPage,
                pattern,
                RegexOptions.Singleline).Cast<Match>().Select(m => m.ToString());
            return ls;
        }

        public static async IAsyncEnumerable<NVDFeed> GetFeedsAsync()
        {
            foreach (var link in GetJsonLinks()) yield return await GetFeedAsync(link);
        }

        public static NVDFeed GetFeed(string link)
        {
            return GetFeedAsync(link).Result;
        }
        
        private static async Task<NVDFeed> GetRecentFeedAsync()
        {
            var link = GetJsonLinks().FirstOrDefault(link => link.ToLower().Contains("recent"));
            return await GetFeedAsync(link);
        }        
        
        private static async Task<NVDFeed> GetModifiedFeedAsync()
        {
            var link = GetJsonLinks().FirstOrDefault(link => link.ToLower().Contains("modified"));
            return await GetFeedAsync(link);
        }

        private static async Task<NVDFeed> GetFeedAsync(string link)
        {
            var fileName = link.Substring(link.LastIndexOf('/') + 1);
            fileName = fileName.Substring(0, fileName.LastIndexOf('.'));
            Console.WriteLine(link);
            using var feedDownloader = new WebClient();
            Stream jsonZippedDataStream = new MemoryStream(feedDownloader.DownloadData(link));
            var zipfile = new ZipArchive(jsonZippedDataStream);
            var entryStream = zipfile.Entries[0].Open();
            return await JsonSerializer.DeserializeAsync<NVDFeed>(entryStream, new JsonSerializerOptions());
        }
    }
}