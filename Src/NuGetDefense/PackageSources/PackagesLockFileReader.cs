using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace NuGetDefense.PackageSources
{
    public class PackagesLockFileReader
    {
        public static bool TryReadFromFile(string path, out IEnumerable<NuGetPackage> nugetPackages)
        {
            var packagesLockFile = PackagesLockFile(path);
            
            if (!packagesLockFile.Exists)
            {
                nugetPackages = Enumerable.Empty<NuGetPackage>();
                return false;
            }

            nugetPackages = PackagesReferencesFromPackagesLockFile(packagesLockFile).AsEnumerable();
            return true;
        }

        private static FileInfo PackagesLockFile(string path)
        {
            const string defaultLockFileName = "packages.lock.json";
            var packagesLockFile = new FileInfo(path);

            if (packagesLockFile.Name.Equals(defaultLockFileName, StringComparison.InvariantCultureIgnoreCase))
                return packagesLockFile;
            
            if ((packagesLockFile.Attributes & FileAttributes.Directory) == FileAttributes.Directory)
                return new FileInfo(Path.Combine(packagesLockFile.FullName, defaultLockFileName));
            
            return new FileInfo(Path.Combine(Path.GetDirectoryName(packagesLockFile.FullName), defaultLockFileName));
        } 

        private static IEnumerable<NuGetPackage> PackagesReferencesFromPackagesLockFile(FileSystemInfo packagesLockFile)
        {
            using var file = File.OpenText(@"TestFiles/packages.lock.json");
            using var reader = new JsonTextReader(file);
            var jObject = JObject.Load(reader);
            
            var dependencies = jObject.GetValue("dependencies").FirstOrDefault();

            if (dependencies == null)
                yield break;
            
            foreach (var jToken in dependencies.Values())
            {
                var dependency = (JProperty) jToken;

                const string directDependencyType = "direct";

                if (!directDependencyType.Equals(dependency.Value["type"].ToString(), StringComparison.InvariantCultureIgnoreCase))
                    continue;
                
                yield return new NuGetPackage
                {
                    Id = dependency.Name,
                    LineNumber = reader.LineNumber,
                    LinePosition = reader.LinePosition,
                    Version = dependency.Value["resolved"].ToString()
                };
            }
        }
    }
}