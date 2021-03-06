
# [![NuGetDefense](images/logo.png)](https://digitalcoyote.github.io/NuGetDefense/)

[![Join the chat at https://gitter.im/NuGetDefense/community](https://badges.gitter.im/NuGetDefense/community.svg)](https://gitter.im/NuGetDefense/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)  [![NuGet version](https://badge.fury.io/nu/NugetDefense.svg)](https://badge.fury.io/nu/NugetDefense)

An MSBuildTask that checks for known vulnerabilities. Inspired by [OWASP SafeNuGet](https://github.com/OWASP/SafeNuGet).
  
## Docs
View the full documentation for NuGetDefense [here](https://digitalcoyote.github.io/NuGetDefense/)
  
## Features  

* Uses Multiple Sources to check for known vulnerabilities in third-party libraries (NuGet packages)
  * [OSS Index](https://ossindex.sonatype.org/) (Caching Coming Soon!)
  * [National Vulnerability Database](https://nvd.nist.gov/) (Optionally Self-Updating)
  * [Google's Open Source Vulnerabilities Database](https://osv.dev/) ([Coming Soon!](https://github.com/digitalcoyote/NuGetDefense/discussions/53))
* Simple installation/configuration: the [NuGet Package](https://www.nuget.org/packages/NuGetDefense/) is all you need.
* Transitive Dependency Checking
  * SDK style projects only (older project format is not supported by the dotnet cli)
  * Uses the versions resolved by the dotnet cli at build
* Project Reference Scanning
  * Scan all projects in a hierarchy by installing NuGet Defense to the top level package ([pre-release](https://www.nuget.org/packages/NuGetDefense/2.1.0-pre0011))
* Allow breaking the build based on severity of vulnerability.
* Ignore specific vulnerabilities/packages.
* Sensitive/Internal Packages filtering
  * Don't send packages that are sensitive/internal to remote vulnerability sources
* Blocklisting NuGet Packages
* Allowlisting NuGet Packages
* MIT Licensed

## Requirements

  - NuGetDefense v1.x is built only in .Net Core 3.1 so you will need the runtime/SDK installed.
  - NuGetDefense v2.x is built only in .Net 5.0 (significantly faster) so you will need the runtime/SDK installed.
  
## How does it work?

  NuGetDefense is a bundled dotnet tool that runs using an [MSBuild ExecTask](https://docs.microsoft.com/en-us/visualstudio/msbuild/exec-task?view=vs-2019) after your project finishes building.

## Love it? Support it!

You can sponsor this project on [Github](https://github.com/sponsors/digitalcoyote) and [Patreon](https://www.patreon.com/codingcoyote). The funds will be used to pay for software licenses and cloud/hardware costs that keep my projects running.
