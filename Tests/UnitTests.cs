using System;
using System.IO;
using Xunit;
using PEye.Utils;

namespace Tests
{
    public class UnitTests
    {
        [Fact]
        public void CalculateMD5_KnownData_ReturnsExpectedHash()
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("hello");
            string md5 = Hashing.CalculateMD5(data);
            // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
            Assert.Equal("5d41402abc4b2a76b9719d911017c592", md5);
        }

        [Fact]
        public void FileUtils_IsPEFile_OnTextFile_ReturnsFalse()
        {
            var tmp = Path.GetTempFileName();
            File.WriteAllText(tmp, "not a pe");
            try
            {
                Assert.False(FileUtils.IsPEFile(tmp));
            }
            finally
            {
                File.Delete(tmp);
            }
        }
    }
}
