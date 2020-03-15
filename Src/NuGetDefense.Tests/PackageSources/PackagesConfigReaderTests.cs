using FluentAssertions;
using NuGetDefense.PackageSources;
using Xunit;

namespace NuGetDefense.Tests.PackageSources
{
    public class PackagesConfigReaderTests
    {
        [Fact]
        public void TryReadFromPackagesConfig_ReturnsFalse_WhenFileDoesNotExist()
        {
            PackagesConfigFileReader.TryReadFromFile(@"non-existing/packages.config", out var packages).Should().BeFalse();
            packages.Should().BeEmpty();
        }
        
        [Fact]
        public void TryReadFromPackagesConfig_ReturnsTrue_WhenFileExists()
        {
            PackagesConfigFileReader.TryReadFromFile(@"TestFiles/packages.config", out var packages).Should().BeTrue();
            packages.Should().NotBeEmpty().And.HaveCount(4);
        }
    }
}