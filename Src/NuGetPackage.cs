namespace NuGetDefense
{
    public class NuGetPackage
    {
        public string Id { get; set; }

        public string Version { get; set; }

        internal string PackageUrl => $@"pkg:nuget/{Id}@{Version}";
        internal int LinePosition { get; set; }
        internal int LineNumber { get; set; }
    }
}