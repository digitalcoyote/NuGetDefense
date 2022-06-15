
# [![NuGetDefense](https://raw.githubusercontent.com/digitalcoyote/NuGetDefense/master/.github/images/logo.png)](https://digitalcoyote.github.io/NuGetDefense/)

[![Join the chat at https://gitter.im/NuGetDefense/community](https://badges.gitter.im/NuGetDefense/community.svg)](https://gitter.im/NuGetDefense/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)  [![NuGet version](https://badge.fury.io/nu/NugetDefense.svg)](https://badge.fury.io/nu/NugetDefense)

An MSBuildTask that checks for known vulnerabilities. Inspired by [OWASP SafeNuGet](https://github.com/OWASP/SafeNuGet).
  
## Docs

View the full documentation for NuGetDefense [here](https://digitalcoyote.github.io/NuGetDefense/)

3.x preview documentation can be found by running `dotnet /path/to/NuGetDefense.dll -?`
  
## Features  

* Uses Multiple Sources to check for known vulnerabilities in third-party libraries (NuGet packages)
  * [OSS Index](https://ossindex.sonatype.org/)
  * [National Vulnerability Database](https://nvd.nist.gov/) (Optionally Self-Updating)
  * [GitHub Security Advisory Database](https://nvd.nist.gov/)
  * [Google's Open Source Vulnerabilities Database](https://osv.dev/) ([Coming Soon!](https://github.com/digitalcoyote/NuGetDefense/discussions/53))
* Simple installation/configuration: the [NuGet Package](https://www.nuget.org/packages/NuGetDefense/) is all you need.
* dotnet Global Tool for those who want to run it manually or just in the CI
* Transitive Dependency Checking
  * SDK style projects only (older project format is not supported by the dotnet cli)
  * Uses the versions resolved by the dotnet cli at build
* Project Reference Scanning
  * Scan all projects in a hierarchy by installing NuGet Defense to the top level package
* Allow breaking the build based on severity of vulnerability.
* Ignore specific vulnerabilities/packages.
* Sensitive/Internal Packages filtering
  * Don't send packages that are sensitive/internal to remote vulnerability sources
* Caching to prevent excess calls and hitting rate limits on API's
* Blocklisting NuGet Packages
* Allowlisting NuGet Packages
* MIT Licensed
  * Consumable NuGet packages for bundling NuGetDefense scanners into your own software

## Requirements

* NuGetDefense v1.x is built only in .Net Core 3.1 so you will need the runtime/SDK installed.
* NuGetDefense v2.x is built only in .Net 5.0 so you will need the runtime/SDK installed. (.Net 5.0 is our of support)
* NuGetDefense v3.x is built only in .Net 6.0 so you will need the runtime/SDK installed.

## Unsupported Versions
* Official Support follows support for the underlying framework.
* Supporters can request support of unsupported versions (such as v2.x running on .Net 5) but are advised to use a supported runtime (for better overall security)
  * .Net 5 projects can use 3.x as long as the .Net 6 runtime is installed.
  
## How does it work?

  NuGetDefense is a bundled dotnet tool that runs using an [MSBuild ExecTask](https://docs.microsoft.com/en-us/visualstudio/msbuild/exec-task?view=vs-2019) after your project finishes building.

## Love it? Support it

You can sponsor this project on [Github](https://github.com/sponsors/digitalcoyote) and [Patreon](https://www.patreon.com/codingcoyote). The funds will be used to pay for software licenses and cloud/hardware costs that keep my projects running.
