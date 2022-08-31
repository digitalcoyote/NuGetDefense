---
title: "NuGetDefense.Lib"
---

# Summary
NuGetDefense.Lib provides programmatic access to all the features of NuGetDefense. The main use is in the Scanner.Scan method which returns the number of vulnerabilities found.

## Scanner

### Scan(Scanoptions)
Scan is the main method and performs the same scan as NuGetDefense

### GetNonSensitivePackages(out Dictionary<string, NuGetPackage[]>)
Reads SensitivePackages in Settings and escapes all characters for Regex, then replaces `*` with `.*` (Regex wild Card for 0 or more of any character). Then returns a list of packages that do not match the wild card strings in SensitivePackages.

## ScanOptions

### Cache
Currently, this only accepts a SqlLiteVulnerabilityCache (with `Path` and `Enabled`) fields. Future versions will include a Type field to support non-local caches.

### CheckReferencedProjects
Boolean used to determine if project referenced are scanned

### CheckTransitiveDependencies
Boolean used to determine if nuget should be used to resolve transitive dependencies

### IgnoreCves
Ignores specific vulnerabilities found in this set when reporting them. CVEs are generally the ID for vulnerabilities, but any ID returned by NuGetDefense will work here.

### IgnorePackages
Ignores specific package id's to ignore.

### ProjectFile
File used to obtain dependency info.

### SettingsFile
Allows loading a NuGetDefense config file

### Tfm
The [TFM or Target Framework Moniker](https://docs.microsoft.com/en-us/dotnet/standard/frameworks#supported-target-frameworks) provided to nuget when getting transitive dependencies.

### VulnDataFile
The File used to store/retrieve NVD Data

### WarnOnly
If True, only emits warnings

## NuGetPackage

### Dependencies
Array of strings that represent the dependencies of this package

### Id
This is the Id defined in the nuspec file and used in package references and the package.json

### Version
Package version

### PackageUrl
The [package url spec](https://github.com/package-url/purl-spec) is a representation of the package ecosystem, ID, and string used to disambiguate this package from similarly named packages in other ecosystems

## VulnerabilityCache
The workhorse of the cache.

### GetUncachedPackagesFunc
Once set, this function spits out an array of packages that need to be checked.

### GetPackageCachedVulnerabilitiesForSource
Once set this function returns an array of cached vulnerabilities

### UpdateCache
Once set this function updates the cache with the results of a scan

### GetSqliteCache
This is a static method that creates a new sqlite cache

## VulnerabilityReport
Reporting object used to gather data for reporting.

### VulnerabilitiesCount
Number of vulnerabilities reported

### Packages
Array of VulnerableNuGetPackage containing vulnerable packages and vulnerability details

## VulnerableNuGetPackage

### Id
ID of the vulnerable nuget package

### PackageUrl
The [package url spec](https://github.com/package-url/purl-spec) is a representation of the package ecosystem, ID, and string used to disambiguate this package from similarly named packages in other ecosystems

### Version
Version of the vulnerable package

### Vulnerabilities
Array of ReportedVulnerability. Contains data about reported vulberabilities for this package

## ReportedVulnerability

### Description
Description of the vulnerability. Usually enough to assess the risk.

### Cve
ID of the vulnerability

### Cwe
[Common Weakness Enumeration](https://cwe.mitre.org/index.html)

### CvssScore
Severity score. Generally the higher the number the worse.

### CvssVector
Access Vector of the vulnerability.

