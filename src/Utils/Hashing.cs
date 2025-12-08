using System;
using System.IO;
using System.Linq; 
using System.Security.Cryptography;
using System.Text;
using PEye.Core;

namespace PEye.Utils
{
    public static class Hashing
    {
        public static HashResult CalculateHashes(string filePath)
        {
            var result = new HashResult
            {
                FilePath = filePath,
                FileSize = new FileInfo(filePath).Length
            };

            byte[] fileBytes = File.ReadAllBytes(filePath);

            result.MD5 = CalculateMD5(fileBytes);
            result.SHA1 = CalculateSHA1(fileBytes);
            result.SHA256 = CalculateSHA256(fileBytes);
            result.Imphash = CalculateImphash(filePath);
            result.Ssdeep = CalculateSsdeep(fileBytes);

            return result;
        }

        public static string CalculateMD5(byte[] data)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(data);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        public static string CalculateSHA1(byte[] data)
        {
            using (var sha1 = SHA1.Create())
            {
                byte[] hash = sha1.ComputeHash(data);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        public static string CalculateSHA256(byte[] data)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(data);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        public static string CalculateImphash(string filePath)
        {
            try
            {
                var peParser = new PEParser(filePath);
                if (!peParser.IsPE)
                    return "N/A";
                var importAnalyzer = new ImportAnalyzer(peParser);
                var imports = importAnalyzer.ParseImports();

                if (imports.Count == 0)
                    return "N/A";

                var sb = new StringBuilder();
                foreach (var lib in imports.OrderBy(l => l.Name.ToLowerInvariant()))
                {
                    foreach (var func in lib.Functions.OrderBy(f => f.Name.ToLowerInvariant()))
                    {
                        sb.Append($"{lib.Name.ToLowerInvariant()}.{func.Name.ToLowerInvariant()},");
                    }
                }

                if (sb.Length == 0)
                    return "N/A";

                string imphashString = sb.ToString().TrimEnd(',');
                using (var md5 = MD5.Create())
                {
                    byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(imphashString));
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return "N/A";
            }
        }

        public static string CalculateSsdeep(byte[] data)
        {
            // Simplified fuzzy hash implementation
            // For production, use actual ssdeep library
            try
            {
                int blockSize = 3;
                while (blockSize * 64 < data.Length)
                    blockSize *= 2;

                return $"{blockSize}:SimpleHash:Placeholder";
            }
            catch
            {
                return "N/A";
            }
        }

        public static string GenerateReport(HashResult hashes)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== FILE HASHES ===\n");
            sb.AppendLine($"File: {Path.GetFileName(hashes.FilePath)}");
            sb.AppendLine($"Size: {hashes.FileSize:N0} bytes\n");
            sb.AppendLine($"MD5:     {hashes.MD5}");
            sb.AppendLine($"SHA1:    {hashes.SHA1}");
            sb.AppendLine($"SHA256:  {hashes.SHA256}");
            sb.AppendLine($"Imphash: {hashes.Imphash}");
            sb.AppendLine($"Ssdeep:  {hashes.Ssdeep}");
            return sb.ToString();
        }
    }

    public class HashResult
    {
        public string FilePath { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public string MD5 { get; set; } = string.Empty;
        public string SHA1 { get; set; } = string.Empty;
        public string SHA256 { get; set; } = string.Empty;
        public string Imphash { get; set; } = string.Empty;
        public string Ssdeep { get; set; } = string.Empty;
    }
}