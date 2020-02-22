namespace NuGetDefense.Configuration
{
    public class BlacklistedPackage
    {
        public NuGetPackage Package { get; set; }
        public string CustomErrorMessage { get; set; }
    }
}