using System.Collections.Generic;
using System.Xml.Serialization;

namespace NuGetDefense
{
    public class NuGetPackage
    {
        public string Id { get; set; }

        public string Version { get; set; }
        
        public string PackageUrl => $@"pkg:nuget/{Id}@{Version}";

    }
}