using System.Collections.Generic;
using System.Text.Json.Serialization;
using System.Xml.Serialization;

namespace NuGetDefense
{
    public class NuGetPackage
    {
        public string Id { get; set; }

        public string Version { get; set; }
        
        public string PackageUrl => $@"pkg:nuget/{Id}@{Version}";
        public int LinePosition { get; set; }
        public int LineNumber { get; set; }
    }
}