namespace NuGetDefense
{
    public class NuGetPackage
    {
        public string[] Dependencies = { };
        public int? LineNumber;
        public int? LinePosition;

        public string Id { get; set; }

        public string Version { get; set; }

        public string PackageUrl => $@"pkg:nuget/{Id}@{Version}";
    }
}