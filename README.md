# NuGetDefense

[![Join the chat at https://gitter.im/NuGetDefense/community](https://badges.gitter.im/NuGetDefense/community.svg)](https://gitter.im/NuGetDefense/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

An MSBuildTask that checks for known vulnerabilities. Inspired by [OWASP SafeNuGet](https://github.com/OWASP/SafeNuGet).
#### Rider
![Example Error Messages in Rider](https://rawcdn.githack.com/digitalcoyote/NuGetDefense/c5e153a627cde0d194daf8500ffb8cab7020e903/ErrorMessages.png)
#### Visual Studio
![Example Error Messages in Visual Studio 2019](https://rawcdn.githack.com/digitalcoyote/NuGetDefense/16150e955e89e21d24c54bb4a03888e9a7b896e5/VSErrorMessages.png)

## Why a new Project?
  1. SafeNuGet hasn't seen a new commit in years  and isn't able to keep up with vulnerable packages.
  2. SafeNuGet doesn't have a license (at all).
  3. A pure MSBuild task [should not use dependencies](https://natemcmaster.com/blog/2017/11/11/msbuild-task-with-dependencies/) and cannot get the desired results without them.
  
## Features  
* Uses Multiple Sources to check for known vulnerabilities in third-party libraries (NuGet packages)
  * [OSS Index](https://ossindex.sonatype.org/)
  * [National Vulnerability Database](https://nvd.nist.gov/) (Optionally Self-Updating)
* Simple installation/configuration: the [NuGet Package](https://www.nuget.org/packages/NuGetDefense/) is all you need.
* Checks dependencies of installed packages based on the target framework.
* Allow breaking the build based on severity of vulnerability.
* Ignore specific vulnerabilities/packages.
* Blacklisting NuGet Packages
* Whitelisting NuGet Packages
* MIT Licensed

## Requirements
  Currently NuGetDefense is built only in .Net Core 3.1 so you will need the runtime/SDK installed.

## How does it work?
  NuGetDefense is a bundled dotnet tool that runs using an [MSBuild ExecTask](https://docs.microsoft.com/en-us/visualstudio/msbuild/exec-task?view=vs-2019) after your project finishes building.

    
## Love it? Support it!
You can sponsor this project on [Github](https://github.com/sponsors/digitalcoyote) and [Patreon](https://www.patreon.com/codingcoyote). The funds will be used to pay for software licenses and cloud/hardware costs that keep my projects running.
