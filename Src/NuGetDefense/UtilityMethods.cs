using System.Linq;
using NuGet.Versioning;

namespace NuGetDefense
{
    public class UtilityMethods
    {
        public static void IgnorePackages(in NuGetPackage[] pkgs, NuGetPackage[] ignorePackages, out NuGetPackage[] unIgnoredPackages)
        {
            unIgnoredPackages = pkgs.Where(p => ignorePackages.All(ip => ip.Id != p.Id || !string.IsNullOrWhiteSpace(ip.Version) && !VersionRange.Parse(ip.Version).Satisfies(new NuGetVersion(p.Version)))).ToArray();
        }
    }
}