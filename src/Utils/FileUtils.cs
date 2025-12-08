using System;
using System.IO;
using System.Linq;

namespace PEye.Utils
{
    public static class FileUtils
    {
        public static bool IsPEFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return false;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    if (fs.Length < 64)
                        return false;

                    byte[] buffer = new byte[2];
                    fs.Read(buffer, 0, 2);

                    // Check MZ signature
                    return buffer[0] == 0x4D && buffer[1] == 0x5A;
                }
            }
            catch
            {
                return false;
            }
        }

        public static string GetFileType(string filePath)
        {
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            
            return extension switch
            {
                ".exe" => "Executable",
                ".dll" => "Dynamic Link Library",
                ".sys" => "System Driver",
                ".scr" => "Screen Saver",
                ".cpl" => "Control Panel",
                ".ocx" => "ActiveX Control",
                ".drv" => "Driver",
                _ => "Unknown PE File"
            };
        }

        public static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        public static void CreateOutputDirectory(string path)
        {
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
        }

        public static string SanitizeFileName(string fileName)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            return string.Join("_", fileName.Split(invalidChars));
        }

        public static bool IsFileLocked(string filePath)
        {
            try
            {
                using (var stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    stream.Close();
                }
                return false;
            }
            catch (IOException)
            {
                return true;
            }
        }

        public static string GetSafeFileName(string filePath)
        {
            return Path.GetFileName(filePath) ?? "unknown";
        }
    }
}