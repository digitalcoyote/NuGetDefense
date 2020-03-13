using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Configuration;
using NuGet.Frameworks;
using NuGet.Packaging;
using NuGet.Packaging.Core;
using NuGet.Protocol.Core.Types;
using NuGet.Resolver;
using NuGet.Versioning;

namespace NuGetDefense
{
    public static class NuGetClient
    {
        private static async Task GetPackageDependencies(PackageIdentity package,
            NuGetFramework framework,
            SourceCacheContext cacheContext,
            ILogger logger,
            IEnumerable<SourceRepository> repositories,
            ISet<SourcePackageDependencyInfo> availablePackages)
        {
            if (availablePackages.Contains(package)) return;

            foreach (var sourceRepository in repositories)
            {
                var dependencyInfoResource = await sourceRepository.GetResourceAsync<DependencyInfoResource>();
                var dependencyInfo = await dependencyInfoResource.ResolvePackage(
                    package, framework, cacheContext, logger, CancellationToken.None);

                if (dependencyInfo == null) continue;

                availablePackages.Add(dependencyInfo);
                foreach (var dependency in dependencyInfo.Dependencies)
                    await GetPackageDependencies(
                        new PackageIdentity(dependency.Id, dependency.VersionRange.MinVersion),
                        framework, cacheContext, logger, repositories, availablePackages);
            }
        }

        public static async Task<List<NuGetPackage>> GetAllPackageDependencies(List<NuGetPackage> pkgs,
            string framework)
        {
            var allPkgs = new List<NuGetPackage>();

            var packagesToInstall = new List<SourcePackageDependencyInfo>();

            var settings = Settings.LoadDefaultSettings(null);
            var sourceRepositoryProvider =
                new SourceRepositoryProvider(new PackageSourceProvider(settings), Repository.Provider.GetCoreV3());

            using var cacheContext = new SourceCacheContext();
            var repositories = sourceRepositoryProvider.GetRepositories();
            var availablePackages = new HashSet<SourcePackageDependencyInfo>(PackageIdentityComparer.Default);

            foreach (var package in pkgs)
            {
                var packageId = package.Id;
                await GetPackageDependencies(
                    new PackageIdentity(package.Id, NuGetVersion.Parse(package.Version)),
                    NuGetFramework.ParseFolder(framework), cacheContext, NullLogger.Instance, repositories,
                    availablePackages);
            }

            var resolverContext = new PackageResolverContext(
                DependencyBehavior.Highest,
                pkgs.Select(p => p.Id).ToArray(),
                Enumerable.Empty<string>(),
                Enumerable.Empty<PackageReference>(),
                Enumerable.Empty<PackageIdentity>(),
                availablePackages,
                sourceRepositoryProvider.GetRepositories().Select(s => s.PackageSource),
                NullLogger.Instance);

            var resolver = new PackageResolver();
            packagesToInstall.AddRange(resolver.Resolve(resolverContext, CancellationToken.None)
                .Select(p => availablePackages.Single(x => PackageIdentityComparer.Default.Equals(x, p))));
            foreach (var package in pkgs)
            {
                package.Dependencies = packagesToInstall.First(p => p.Id == package.Id).Dependencies.Select(dep => dep.Id).ToArray();
            }

            return pkgs;
        }
    }
}