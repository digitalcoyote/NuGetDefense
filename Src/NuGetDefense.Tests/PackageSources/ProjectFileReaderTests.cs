using FluentAssertions;
using NuGetDefense.PackageSources;
using Xunit;

namespace NuGetDefense.Tests.PackageSources
{
    public class ProjectFileReaderTests
    {
        [Fact]
        public void TryReadFromProjectFile_ReturnsFalse_WhenFileDoesNotExist()
        {
            ProjectFileReader.TryReadFromFile(@"non/existing.csproj", out var packages).Should().BeFalse();
            packages.Should().BeEmpty();
        }
        
        [Fact]
        public void TryReadFromProjectFile_ReturnsTrue_WhenFileExists()
        {
            ProjectFileReader.TryReadFromFile(@"TestFiles/NetCoreConsoleApp.csproj", out var packages).Should().BeTrue();
            packages.Should().NotBeEmpty().And.HaveCount(1);
        }
    }
}