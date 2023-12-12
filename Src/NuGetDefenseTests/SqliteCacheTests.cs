using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;
using NuGetDefense;
using NuGetDefense.Core;
using Xunit;

namespace NuGetDefenseTests;

public class SqliteCacheTests : IDisposable
{
    private const string TestSourceID = "TestSource";
    private const string cacheFile = "./Test.sqlite";

    public SqliteCacheTests()
    {
        if (File.Exists(cacheFile)) File.Delete(cacheFile);
        SqlLiteVulnerabilityCache.CreateNewSqlLiteCache(cacheFile);
    }

    private SqlLiteVulnerabilityCache cache => new(cacheFile);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        File.Delete(cacheFile);
    }

    [Fact]
    public void UpdateCacheNoVulns()
    {
        const string packageId = "test_package";
        const string packageVersion = "1.2.3-123Test";
        var pkgs = new[]
        {
            new NuGetPackage { Version = packageVersion, Dependencies = Array.Empty<string>(), Id = packageId }
        };

        cache.UpdateCache(new(), pkgs, TestSourceID);
        Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = new();
        cache.GetPackageCachedVulnerabilitiesForSource(pkgs[0], TestSourceID, ref vulnDict);
        Assert.Empty(vulnDict);
        cache.GetPackagesCachedVulnerabilitiesForSource(pkgs, TestSourceID, ref vulnDict);
        Assert.Empty(vulnDict);
        Assert.Empty(cache.GetUncachedPackages(pkgs, TimeSpan.FromDays(1), TestSourceID, out var cachedPkgs));
        Assert.Collection(cachedPkgs, p => pkgs.Contains(p));
    }

    [Fact]
    public void UpdateCacheWithVulnsCached()
    {
        const string packageId = "test_package";
        const string packageVersion = "1.2.3-123Test";
        var pkgs = new[]
        {
            new NuGetPackage { Version = "4.5.2", Dependencies = Array.Empty<string>(), Id = "no_vulns" },
            new NuGetPackage { Version = packageVersion, Dependencies = Array.Empty<string>(), Id = packageId }
        };

        Dictionary<string, Dictionary<string, Vulnerability>> vulns = new()
        {
            {
                pkgs[1].PackageUrl.ToLower(),
                new()
                {
                    {
                        "TestCVE",
                        new("TestCVE", 1.0, "test", "TestDescription", new[] { "ref1", "ref2" }, Vulnerability.AccessVectorType.NETWORK, "TestVendor")
                    }
                }
            }
        };
        cache.UpdateCache(vulns, pkgs, TestSourceID);
        Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = new();
        Dictionary<string, Dictionary<string, Vulnerability>> vulnDict2 = new();

        cache.GetPackageCachedVulnerabilitiesForSource(pkgs[0], TestSourceID, ref vulnDict);
        Assert.Empty(vulnDict);

        cache.GetPackageCachedVulnerabilitiesForSource(pkgs[1], TestSourceID, ref vulnDict2);
        Assert.Single(vulnDict2);
        Assert.True(vulnDict2.ContainsKey(pkgs[1].PackageUrl), $"vulnDict2 does not contain key: {pkgs[1].PackageUrl}");
        Assert.True(vulnDict2[pkgs[1].PackageUrl].ContainsKey("TestCVE"));

        cache.GetPackagesCachedVulnerabilitiesForSource(pkgs, TestSourceID, ref vulnDict);
        Assert.True(vulnDict.Count == 1 && vulnDict.ContainsKey(pkgs[1].PackageUrl) && vulnDict[pkgs[1].PackageUrl].ContainsKey("TestCVE"));

        Assert.Empty(cache.GetUncachedPackages(pkgs, TimeSpan.FromDays(1), TestSourceID, out var cachedPkgs));
        Assert.True(cachedPkgs.All(p => pkgs.Contains(p)));
    }

    [Fact, Issue(138)]
    public void VulnerabilityUpsertSucceedsWhenVulnerabilityExists()
    {
        // Arrange
        const string packageId = "test_package";
        const string packageVersion = "1.2.3-123Test";
        var pkgs = new[]
        {
            new NuGetPackage { Version = "4.5.2", Dependencies = Array.Empty<string>(), Id = "no_vulns" },
            new NuGetPackage { Version = packageVersion, Dependencies = Array.Empty<string>(), Id = packageId }
        };

        Dictionary<string, Dictionary<string, Vulnerability>> vulns = new()
        {
            {
                pkgs[1].PackageUrl.ToLower(),
                new()
                {
                    {
                        "TestCVE",
                        new("TestCVE", 1.0, "test", "TestDescription", new[] { "ref1", "ref2" }, Vulnerability.AccessVectorType.NETWORK, "TestVendor")
                    }
                }
            }
        };

        // Act
        cache.UpdateCache(vulns, pkgs, TestSourceID);
        cache.UpdateCache(vulns, pkgs, TestSourceID);  // Insert it again, simulating a refresh

        Dictionary<string, Dictionary<string, Vulnerability>> vulnerabilities = new();
        cache.GetPackageCachedVulnerabilitiesForSource(pkgs[1], TestSourceID, ref vulnerabilities);

        // Assert
        Assert.Equal(vulns[pkgs[1].PackageUrl.ToLower()].Keys.First(), vulnerabilities.First().Value.Keys.First());
    }

    [Fact]
    public void VulnerabilityUpsertSucceedsWhenVulnerabilityDoesNotExsist()
    {
        // Arrange
        const string packageId = "test_package";
        const string packageVersion = "1.2.3-123Test";
        var pkgs = new[]
        {
            new NuGetPackage { Version = "4.5.2", Dependencies = Array.Empty<string>(), Id = "no_vulns" },
            new NuGetPackage { Version = packageVersion, Dependencies = Array.Empty<string>(), Id = packageId }
        };

        Dictionary<string, Dictionary<string, Vulnerability>> vulns = new()
        {
            {
                pkgs[1].PackageUrl.ToLower(),
                new()
                {
                    {
                        "TestCVE",
                        new("TestCVE", 1.0, "test", "TestDescription", new[] { "ref1", "ref2" }, Vulnerability.AccessVectorType.NETWORK, "TestVendor")
                    }
                }
            }
        };

        // Act
        cache.UpdateCache(vulns, pkgs, TestSourceID);
        Dictionary<string, Dictionary<string, Vulnerability>> vulnerabilities = new();
        cache.GetPackageCachedVulnerabilitiesForSource(pkgs[1], TestSourceID, ref vulnerabilities);

        // Assert
        Assert.Equal(vulns[pkgs[1].PackageUrl.ToLower()].Keys.First(), vulnerabilities.First().Value.Keys.First());
    }
}