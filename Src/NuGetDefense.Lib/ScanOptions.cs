using System.Collections.Generic;
using System.IO;

namespace NuGetDefense
{
    public class ScanOptions
    {
        /// <summary>
        ///     Scans projects referenced by the current project as well
        /// </summary>
        public bool CheckReferencedProjects = false;

        /// <summary>
        ///     Includes Transitive Dependencies when possible
        /// </summary>
        public bool CheckTransitiveDependencies = false;

        /// <summary>
        ///     CVE's to ignore when scanning
        /// </summary>
        public IEnumerable<string> IgnoreCves = System.Array.Empty<string>();

        /// <summary>
        ///     Packages to ignore when scanning
        /// </summary>
        public IEnumerable<string> IgnorePackages = System.Array.Empty<string>();

        /// <summary>
        ///     File used to obtain the dependencies
        /// </summary>
        public FileInfo ProjectFile;

        /// <summary>
        ///     File to use for Settings
        /// </summary>
        public FileInfo SettingsFile;

        /// <summary>
        ///     Target Framework Moniker
        /// </summary>
        public string Tfm;

        /// <summary>
        ///     location of NVD Vulnerability File
        /// </summary>
        public FileInfo VulnDataFile;

        /// <summary>
        ///     Only Provide warnings and do not fail
        /// </summary>
        public bool WarnOnly = false;

        /// <summary>
        /// Cache to use for remote vulnerability sources
        /// </summary>
        public SqlLiteVulnerabilityCache Cache;
    }
}