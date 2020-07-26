using System;

namespace NuGetDefense.Configuration
{
    public class BuildErrorSettings
    {
        public Severity ErrorSeverityThreshold
        {
            get
            {
                if (CVSS3Threshold > 8.9) return Severity.Critical;
                if (CVSS3Threshold > 6.9) return Severity.High;
                if (CVSS3Threshold > 3.9) return Severity.Medium;
                if (CVSS3Threshold > 0) return Severity.Low;
                return CVSS3Threshold < 0 ? Severity.Any : Severity.None;
            }
            set
            {
                CVSS3Threshold = value switch
                {
                    Severity.Any => -1,
                    Severity.None => 0,
                    Severity.Low => 0.1,
                    Severity.Medium => 4.0,
                    Severity.High => 7.0,
                    Severity.Critical => 9.0,
                    _ => CVSS3Threshold
                };
            }
        }

        public double CVSS3Threshold { get; set; } = -1;

        /// <summary>
        ///     List Package Id and Version/Range to be ignored
        ///     (https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges-and-wildcards)
        ///     Version is "any" if omitted
        /// </summary>
        public NuGetPackage[] IgnoredPackages { get; set; } =
        {
            new NuGetPackage
            {
                Id = "NugetDefense",
                Version = "1.0.8.0"
            }
        };

        /// <summary>
        ///     List CVE to be ignored
        ///     (https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges-and-wildcards)
        /// </summary>
        public string[] IgnoredCvEs { get; set; } =
        {
        };

        /// <summary>
        ///     List Package Id and Version/Range to be Allowed
        ///     (https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges-and-wildcards)
        ///     Version is "any" if omitted
        /// </summary>
        public NuGetPackage[] AllowedPackages { get; set; } = { };

        [Obsolete("Here for support of old config files")]
        public NuGetPackage[] WhitelistedPackages
        {
            get => AllowedPackages;
            set => AllowedPackages = value;
        }

        /// <summary>
        ///     List Package Id and Version/Range to be Blocked
        ///     (https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges-and-wildcards)
        ///     Version is "any" if omitted
        /// </summary>
        public BlockedPackage[] BlockedPackages { get; set; } = { };

        [Obsolete("Here for support of old config files")]
        public NuGetPackage[] BlacklistedPackages
        {
            get => AllowedPackages;
            set => AllowedPackages = value;
        }
    }
}