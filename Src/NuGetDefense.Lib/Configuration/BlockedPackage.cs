namespace NuGetDefense.Configuration;

public class BlockedPackage
{
    public NuGetPackage? Package { get; set; }
    public string? CustomErrorMessage { get; set; }
}