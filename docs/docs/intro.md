---
sidebar_position: 1
---

# Introduction

NuGetDefense is a crossplatform MSBuildTask packed into a nugetPackage and a dotnet Global Tool that checks for known vulnerabilities. Inspired by [OWASP SafeNuGet](https://github.com/OWASP/SafeNuGet).

## What Does That Really Mean?

NuGet Defense is a tool you can use to reduce vulnerabilities in your project that are introduced by the NuGet packages you referenced.

## How Do I Use It?

install the NuGetDefense package and the base settings should get you going.

## Can I Use It?

NuGetDefense is proudly [Licensed](https://github.com/digitalcoyote/NuGetDefense/blob/master/LICENSE) so you can:

* Use it in an open source project
* Use it in a closed source project
* Rebrand it and build an enterprise offering on top of it

## What Are the Alternatives?

 * ### [dotnet-retire](https://github.com/RetireNet/dotnet-retire):
   * A dotnet CLI extension to check your project for known vulnerabilities.
 * ### [SafeNuGet](https://github.com/OWASP/SafeNuGet):
   * An MsBuild task to warn about insecure NuGet libraries. (No Longer Maintained)
 * ### [DevAudit](https://github.com/sonatype-nexus-community/DevAudit):
   * A security auditing tool targeted at developers and teams adopting DevOps and DevSecOps that detects security vulnerabilities at multiple levels of the solution stack.
 * ### [Snyk CLI](https://support.snyk.io/hc/en-us/articles/360003812458-Getting-started-with-the-CLI):
   * The Snyk CLI, connects to snyk.io over https, authenticates your machine with your account, and then helps you find and fix known vulnerabilities in your dependencies, both manually and as part of your continuous integration (CI (Build)) system.
 * ### [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/):
   * Dependency-Check is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project’s dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.
 * ### [dotnet](https://docs.microsoft.com/en-us/dotnet/core/tools/dotnet-list-package):
   * `dotnet list package --vulnerable` does list vulnerable packages using GitHub's Security Advisory Database, but the output is sparse and sometimes less than useful