using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Invocation;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Serialization;
using ByteDev.DotNet.Project;
using ByteDev.DotNet.Solution;
using NuGet.Versioning;
using NuGetDefense.Configuration;
using NuGetDefense.Core;
using NuGetDefense.OSSIndex;
using Serilog;
using static NuGetDefense.UtilityMethods;

namespace NuGetDefense
{
    public static class Program
    {
        /// <summary>
        ///     args[0] is expected to be the path to the project file.
        /// </summary>
        /// <param name="args"></param>
        private static int Main(string[] args)
        {
            var projFileOption = new Option<FileInfo>("--project-file", "Project or Solution File to scan");
            projFileOption.AddAlias("-p");
            projFileOption.AddAlias("--project");
            projFileOption.AddAlias("--solution");
            
            var targetFrameworkMonikerOption = new Option<string>("--target-framework-moniker", "Framework to use when detecting versions for 'sdk style' projects");
            targetFrameworkMonikerOption.AddAlias("--tfm");
            targetFrameworkMonikerOption.AddAlias("--framework");
            var settingsOption = new Option<FileInfo>("--settings-file", ()=> null, "Path to Settings File (ex. NuGetDefense.json)");
            settingsOption.AddAlias("--nugetdefense-settings");
            settingsOption.AddAlias("--nugetdefense-json");
            var vulnerabilityDataBinOption = new Option<FileInfo>("--vulnerability-data-bin", "Path to VulnerabilityData for NVD Scanner (ex. VulnerabilityData.bin)");
            vulnerabilityDataBinOption.AddAlias("--nvd-data");
            vulnerabilityDataBinOption.AddAlias("--nvd-data-bin");
            vulnerabilityDataBinOption.AddAlias("--nvd-bin");
            vulnerabilityDataBinOption.AddAlias("--vulnerability-bin");
            vulnerabilityDataBinOption.AddAlias("--vulnerability-data");
            var warnOnlyOption = new Option<bool>("--warn-only", ()=> false, "Disables errors that would break a build, but outputs warnings for each report");
            warnOnlyOption.AddAlias("--do-not-break");
            warnOnlyOption.AddAlias("--warn");
            var checkTransitiveDependenciesOption = new Option<bool>("--check-transitive-dependencies",()=> true , "Enables scanning of transitive dependencies");
            checkTransitiveDependenciesOption.AddAlias("--check-transitive");
            checkTransitiveDependenciesOption.AddAlias("--transitive");
            checkTransitiveDependenciesOption.AddAlias("--check-dependencies");
            checkTransitiveDependenciesOption.AddAlias("--dependencies");
            var checkProjectReferencesOption = new Option<bool>("--check-project-references", ()=> false, "Enables scanning projects referenced by the target project");
            checkProjectReferencesOption.AddAlias("--check-referenced-projects");
            checkProjectReferencesOption.AddAlias("--check-referenced");
            checkProjectReferencesOption.AddAlias("--check-references");
            checkProjectReferencesOption.AddAlias("--references");
            checkProjectReferencesOption.AddAlias("--referenced-projects");
            var ignoredCvesOption = new Option<string[]>("--ignore-cves", Array.Empty<string>, "Adds listed vulnerabilities to a list that is ignored when reporting");
            ignoredCvesOption.AddAlias("--ignore-vulns");
            var ignorePackagesOption = new Option<string[]>("--ignore-packages", Array.Empty<string>,"Adds names to a list of packages to ignore");
            var rootCommand = new RootCommand
            {
                projFileOption,
                targetFrameworkMonikerOption,
                settingsOption,
                vulnerabilityDataBinOption,
                warnOnlyOption,
                checkTransitiveDependenciesOption,
                checkProjectReferencesOption,
                ignorePackagesOption,
                ignoredCvesOption
            };

            rootCommand.Handler = CommandHandler.Create<FileInfo, string, FileInfo, FileInfo, bool, bool, bool, string[], string[], InvocationContext>(Scan);
            return rootCommand.InvokeAsync(args).Result;
        }
        
        public static void Scan(FileInfo projectFile,
            string tfm,
            FileInfo settingsFile,
            FileInfo vulnDataFile,
            bool warnOnly,
            bool checkTransitiveDependencies,
            bool checkReferencedProjects,
            string[] ignorePackages,
            string[] ignoreCves,
            InvocationContext commandContext)
        {
            commandContext.ExitCode = new Scanner().Scan(projectFile,
                tfm,
                settingsFile,
                vulnDataFile,
                warnOnly,
                checkTransitiveDependencies,
                checkReferencedProjects,
                ignorePackages,
                ignoreCves);
        }
    }
}