namespace NuGetDefense
{
    public class NuGetPackage
    {
        internal string[] Dependencies = { };
        internal int? LineNumber;
        internal int? LinePosition;
        public string Id { get; set; }

        public string Version { get; set; }

        internal string PackageUrl => $@"pkg:nuget/{Id}@{Version}";
    }
}