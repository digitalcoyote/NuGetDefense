# NuGetDefense
An MSBuildTask that checks for known vulnerabilities. Inspired by [OWASP SafeNuGet](https://github.com/OWASP/SafeNuGet).

## Why a new Project?
  1. SafeNuGet hasn't seen a new commit in years  and isn't able to keep up with vulnerable packages.
  2. SafeNuGet doesn't have a license (at all).
  3. A pure MSBuild task [should not use dependencies](https://natemcmaster.com/blog/2017/11/11/msbuild-task-with-dependencies/) and cannot get the desired results without them.
  
## (Planned) Features
  
    * Reference the [National Vulnerability Database](https://nvd.nist.gov/).
    * Use [OSS Index](https://ossindex.sonatype.org/) to check for Open Source Software culnerabilities.
    * Allow breaking the build based on severity of vulnerability.
    * MIT Licensed
    * Simple Installation/Configuration
    
## Love it? Support it!
You can click the sponsor button at the top of this repo or sponsor this project on [Github](https://github.com/sponsors/digitalcoyote) and [Patreon](https://www.patreon.com/codingcoyote). The funds will be used to pay for software licenses and cloud/hardware costs that keep my projects running.
