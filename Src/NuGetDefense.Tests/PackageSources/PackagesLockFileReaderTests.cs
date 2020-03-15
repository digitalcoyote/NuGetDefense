using FluentAssertions;
using NuGetDefense.PackageSources;
using Xunit;

namespace NuGetDefense.Tests.PackageSources
{
    public class PackagesLockFileReaderTests
    {
        [Fact]
        public void TryReadFromFile_ReturnsFalse_WhenFileDoesNotExist()
        {
            PackagesLockFileReader.TryReadFromFile(@"non-existing/packages.lock.json", out var packages).Should()
                .BeFalse();
            packages.Should().BeEmpty();
        }

        [Theory]
        [InlineData(@"TestFiles/packages.lock.json")]
        [InlineData(@"TestFiles/test.csproj")]
        [InlineData("TestFiles")]
        public void TryReadFromFile_ReturnsTrue_WhenFileExists(string path)
        {
            PackagesLockFileReader.TryReadFromFile(path, out var packages).Should().BeTrue();
            packages.Should().NotBeEmpty().And.HaveCount(3);
        }
    }
}