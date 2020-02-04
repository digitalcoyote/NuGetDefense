using System.Text.Json.Serialization;

namespace NuGetDefense.OSSIndex
{
    public class ComponentReport
    {
        /// <summary>
        /// Description of the package
        /// </summary>
        [JsonPropertyName("description")]
        public string Description { get; set; }
        
        /// <summary>
        /// packageUrl for this package
        /// </summary>
        [JsonPropertyName("coordinates")]
        public string Coordinates { get; set; }

        /// <summary>
        /// Component Details Reference
        /// </summary>
        [JsonPropertyName("reference")]
        public string Reference { get; set; }

        [JsonPropertyName("vulnerabilities")]
        public ComponentReportVulnerability[] Vulnerabilities { get; set; }
    }
}