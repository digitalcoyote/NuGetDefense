using System.Collections.Generic;
using System.Linq;
using NuGet.Versioning;

namespace NuGetDefense;

public static class UtilityMethods
{
    public static void IgnorePackages(in NuGetPackage[] pkgs, NuGetPackage[] ignorePackages, out NuGetPackage[] unIgnoredPackages)
    {
        unIgnoredPackages = pkgs.Where(p =>
            ignorePackages.All(ip => ip.Id != p.Id || (!string.IsNullOrWhiteSpace(ip.Version) && !VersionRange.Parse(ip.Version).Satisfies(new(p.Version))))).ToArray();
    }

    public static void AddDistinctPackages(this List<NuGetPackage> pkgs, IEnumerable<NuGetPackage> newPkgs)
    {
        foreach (var pkg in newPkgs)
        {
            if (pkgs.Any(p => p.Id == pkg.Id && p.Version == pkg.Version)) continue;

            pkgs.Add(pkg);
        }
    }
}