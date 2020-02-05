# NuGetDefense
An MSBuildTask that checks for known vulnerabilities. Inspired by [OWASP SafeNuGet](https://github.com/OWASP/SafeNuGet).

## Why a new Project?
  1. SafeNuGet hasn't seen a new commit in years  and isn't able to keep up with vulnerable packages.
  2. SafeNuGet doesn't have a license (at all).
  3. A pure MSBuild task [should not use dependencies](https://natemcmaster.com/blog/2017/11/11/msbuild-task-with-dependencies/) and cannot get the desired results without them.
  
## Features  
* Uses [OSS Index](https://ossindex.sonatype.org/) to check for Open Source Software culnerabilities.
* MIT Licensed
* Simple Installation/Configurationa simple [NuGet Package](https://www.nuget.org/packages/NuGetDefense/) is all you need.

## Planned Features
* Reference the [National Vulnerability Database](https://nvd.nist.gov/).
* Allow breaking the build based on severity of vulnerability.
* Ignore specific vulnerabilities/packages.

## Requirements
  Currently NuGetDefense is built only in .Net Core 3.1 so you will need the runtime/SDK installed.

## How does it work?
  NuGetDefense is a bundled dotnet tool that runs using an [MSBuild ExecTask](https://docs.microsoft.com/en-us/visualstudio/msbuild/exec-task?view=vs-2019) after your project finishes building.

    
## Love it? Support it!
You can click the sponsor button at the top of this repo or sponsor this project on [Github](https://github.com/sponsors/digitalcoyote) and [Patreon](https://www.patreon.com/codingcoyote). The funds will be used to pay for software licenses and cloud/hardware costs that keep my projects running.
