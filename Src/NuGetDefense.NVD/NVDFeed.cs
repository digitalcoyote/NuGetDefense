using System;
using System.Text.Json.Serialization;

namespace NuGetDefense.NVD
{
    public class NVDFeed
    {
        [JsonPropertyName("CVE_data_type")] public string CveDataType { get; set; }

        [JsonPropertyName("CVE_data_format")] public string CveDataFormat { get; set; }

        [JsonPropertyName("CVE_data_version")] public string CveDataVersion { get; set; }

        [JsonPropertyName("CVE_data_numberOfCVEs")]
        public string NumberOfCves { get; set; }

        [JsonPropertyName("CVE_data_timestamp")]
        public DateTime TimeStamp { get; set; }

        [JsonPropertyName("CVE_Items")] public FeedVulnerabilities[] CveItems { get; set; }
    }
}