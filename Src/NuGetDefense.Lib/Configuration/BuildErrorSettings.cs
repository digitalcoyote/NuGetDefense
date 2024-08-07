using System;

namespace NuGetDefense.Configuration;

public class BuildErrorSettings
{
    public Severity ErrorSeverityThreshold
    {
        get
        {
            return Cvss3Threshold switch
            {
                > 8.9M => Severity.Critical,
                > 6.9M => Severity.High,
                > 3.9M => Severity.Medium,
                > 0 => Severity.Low,
                0 => Severity.None,
                < 0 => Severity.Any
            };
        }
        set
        {
            Cvss3Threshold = value switch
            {
                Severity.Any => -1,
                Severity.None => 0,
                Severity.Low => 0.1M,
                Severity.Medium => 4.0M,
                Severity.High => 7.0M,
                Severity.Critical => 9.0M,
                _ => Cvss3Threshold
            };
        }
    }

    public decimal Cvss3Threshold { get; set; } = -1;

    /// <summary>
    ///     List Package Id and Version/Range to be ignored
    ///     (https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges-and-wildcards)
    ///     Version is "any" if omitted
    /// </summary>
    public NuGetPackage[]? IgnoredPackages { get; set; } =
    [
        new() { Id = "NugetDefense" }
    ];

    /// <summary>
    ///     List CVE to be ignored
    ///     (https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges-and-wildcards)
    /// </summary>
    public string[]? IgnoredCvEs { get; set; } =
    [
    ];

    /// <summary>
    ///     List Package Id and Version/Range to be Allowed
    ///     (https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges-and-wildcards)
    ///     Version is "any" if omitted
    /// </summary>
    public NuGetPackage[]? AllowedPackages { get; set; } = [];

    /// <summary>
    /// Old name for <see cref="AllowedPackages"/>.
    /// </summary>
    [Obsolete("Here for support of old config files")]
    public NuGetPackage[]? WhiteListedPackages { get; set; } = [];


    /// <summary>
    ///     List Package Id and Version/Range to be Blocked
    ///     (https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges-and-wildcards)
    ///     Version is "any" if omitted
    /// </summary>
    public BlockedPackage[]? BlockedPackages { get; set; } = [];

    /// <summary>
    /// Old name for <see cref="BlockedPackages"/>.
    /// </summary>
    [Obsolete("Here for support of old config files")]
    public BlockedPackage[]? BlacklistedPackages { get; set; } = [];
}