using System.Collections.Generic;
using System.Threading.Tasks;
using NuGetDefense.NVD;

namespace NVDFeedImporter
{
    internal class Program
    {
        private const string BinName = "VulnerabilityData.bin";

        private static async Task Main(string[] args)
        {
            var vulnDict =
                new Dictionary<string, Dictionary<string, VulnerabilityEntry>>();
            await foreach (var feed in FeedUpdater.GetFeedsAsync())
                FeedUpdater.AddFeedToVulnerabilityData(feed, vulnDict);

            VulnerabilityData.SaveToBinFile(vulnDict, BinName);
        }
    }
}