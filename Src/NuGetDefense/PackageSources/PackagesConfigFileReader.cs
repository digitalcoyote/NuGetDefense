using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;

namespace NuGetDefense.PackageSources
{
    public static class PackagesConfigFileReader
    {
        public static bool TryReadFromFile(string path, out IEnumerable<NuGetPackage> nugetPackages)
        {
            var packagesConfigPath = new FileInfo(path);
            if (!packagesConfigPath.Exists)
            {
                nugetPackages = Enumerable.Empty<NuGetPackage>();
                return false;
            }
            
            nugetPackages = PackageXmlNodesFromPackagesConfig(packagesConfigPath)
                .Select(ToNugetPackage)
                .AsEnumerable();
            
            return true;
        }

        private static IEnumerable<XElement> PackageXmlNodesFromPackagesConfig(FileSystemInfo packagesConfigPath) =>
            XElement.Load(packagesConfigPath.FullName, LoadOptions.SetLineInfo).DescendantsAndSelf("package");

        private static NuGetPackage ToNugetPackage(XElement xElement) =>
            new NuGetPackage
            {
                Id = xElement.Attribute("id")?.Value, 
                Version = xElement.Attribute("version")?.Value,
                LineNumber = ((IXmlLineInfo) xElement).LineNumber,
                LinePosition = ((IXmlLineInfo) xElement).LinePosition
            };
    }
}