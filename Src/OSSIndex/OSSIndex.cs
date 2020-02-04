using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;

namespace NuGetDefense.OSSIndex
{
 
    /// <summary>
    /// Handles interaction with the OSS Index Rest API (https://ossindex.sonatype.org/doc/rest) 
    /// </summary>
    public static class OssIndex
    {
        private const string ResponseContentType = "application/vnd.ossindex.component-report.v1+json";
        
        /// <summary>
        /// Gets vulnerabilities for a single NuGet Package.
        /// </summary>
        /// <param name="pkg">NuGetPackage to check</param>
        /// <returns></returns>
        private static async Task<ComponentReport> GetReportForPackageAsync(NuGetPackage pkg)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(ResponseContentType));
                var response = await client.GetStringAsync($"https://ossindex.sonatype.org/api/v3/component-report/{pkg.PackageUrl}");
                return JsonSerializer.Deserialize<ComponentReport>(response,  new JsonSerializerOptions());
            }
        }

        /// <summary>
        /// Gets Vulnerabilities for a set of NuGet Packages
        /// </summary>
        /// <param name="pkgs"> Packages to Check</param>
        /// <returns></returns>
        private static async Task<ComponentReport[]> GetReportsForPackagesAsync(IEnumerable<NuGetPackage> pkgs)
        {
            using var client = new HttpClient();
            var content =  JsonSerializer.Serialize(pkgs);
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(ResponseContentType));
            return await JsonSerializer.DeserializeAsync<ComponentReport[]>(await client
                .PostAsync("https://ossindex.sonatype.org/api/v3/component-report",
                    new StringContent(content, Encoding.UTF8, ResponseContentType)).Result.Content.ReadAsStreamAsync(),  new JsonSerializerOptions());
        }

        /// <summary>
        /// Gets vulnerabilities for a single NuGet Package
        /// </summary>
        /// <param name="pkg">NuGetPAckage to check</param>
        /// <returns></returns>
        public static ComponentReportVulnerability[] GetVulnerabilitiesForPackage(NuGetPackage pkg)
        {
            return GetReportForPackageAsync(pkg).Result.Vulnerabilities;
        }
        
        /// <summary>
        /// Gets Vulnerabilities for a set of NuGet Packages
        /// </summary>
        /// <param name="pkgs"> Packages to Check</param>
        /// <returns></returns>
        public static IEnumerable<ComponentReport> GetVulnerabilitiesForPackages(IEnumerable<NuGetPackage> pkgs)
        {
            return GetReportsForPackagesAsync(pkgs).Result.Where(report => report.Vulnerabilities.Length > 0);
        }
    }
}