using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PEye.Core
{
    public class StringExtractor
    {
        private readonly int _minLength;
        private readonly bool _includeUnicode;

        public StringExtractor(int minLength = 4, bool includeUnicode = true)
        {
            _minLength = minLength;
            _includeUnicode = includeUnicode;
        }

        public ExtractedStrings Extract(byte[] data)
        {
            var result = new ExtractedStrings
            {
                AsciiStrings = ExtractAscii(data),
                UnicodeStrings = _includeUnicode ? ExtractUnicode(data) : new List<ExtractedString>()
            };

            // Categorize strings
            AnalyzeStrings(result);

            return result;
        }

        private List<ExtractedString> ExtractAscii(byte[] data)
        {
            var strings = new List<ExtractedString>();
            var currentString = new StringBuilder();
            int startOffset = -1;

            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];

                // Printable ASCII range (32-126) or common whitespace
                if ((b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13)
                {
                    if (currentString.Length == 0)
                        startOffset = i;

                    currentString.Append((char)b);
                }
                else
                {
                    if (currentString.Length >= _minLength)
                    {
                        strings.Add(new ExtractedString
                        {
                            Value = currentString.ToString(),
                            Offset = startOffset,
                            Type = StringType.Ascii,
                            Encoding = "ASCII"
                        });
                    }
                    currentString.Clear();
                    startOffset = -1;
                }
            }

            // Handle last string
            if (currentString.Length >= _minLength)
            {
                strings.Add(new ExtractedString
                {
                    Value = currentString.ToString(),
                    Offset = startOffset,
                    Type = StringType.Ascii,
                    Encoding = "ASCII"
                });
            }

            return strings;
        }

        private List<ExtractedString> ExtractUnicode(byte[] data)
        {
            var strings = new List<ExtractedString>();
            var currentString = new StringBuilder();
            int startOffset = -1;

            for (int i = 0; i < data.Length - 1; i += 2)
            {
                byte b1 = data[i];
                byte b2 = data[i + 1];

                // Wide character (little-endian UTF-16)
                if (b2 == 0 && ((b1 >= 32 && b1 <= 126) || b1 == 9 || b1 == 10 || b1 == 13))
                {
                    if (currentString.Length == 0)
                        startOffset = i;

                    currentString.Append((char)b1);
                }
                else
                {
                    if (currentString.Length >= _minLength)
                    {
                        strings.Add(new ExtractedString
                        {
                            Value = currentString.ToString(),
                            Offset = startOffset,
                            Type = StringType.Unicode,
                            Encoding = "UTF-16LE"
                        });
                    }
                    currentString.Clear();
                    startOffset = -1;
                }
            }

            // Handle last string
            if (currentString.Length >= _minLength)
            {
                strings.Add(new ExtractedString
                {
                    Value = currentString.ToString(),
                    Offset = startOffset,
                    Type = StringType.Unicode,
                    Encoding = "UTF-16LE"
                });
            }

            return strings;
        }

        private void AnalyzeStrings(ExtractedStrings extracted)
        {
            var allStrings = extracted.AsciiStrings.Concat(extracted.UnicodeStrings).ToList();

            foreach (var str in allStrings)
            {
                str.Category = CategorizeString(str.Value);
                str.IsSuspicious = IsSuspicious(str.Value, str.Category);
            }

            // Populate categorized lists
            extracted.Urls = allStrings.Where(s => s.Category == StringCategory.Url).ToList();
            extracted.FilePaths = allStrings.Where(s => s.Category == StringCategory.FilePath).ToList();
            extracted.RegistryKeys = allStrings.Where(s => s.Category == StringCategory.RegistryKey).ToList();
            extracted.IpAddresses = allStrings.Where(s => s.Category == StringCategory.IpAddress).ToList();
            extracted.Emails = allStrings.Where(s => s.Category == StringCategory.Email).ToList();
            extracted.SuspiciousStrings = allStrings.Where(s => s.IsSuspicious).ToList();
        }

        private StringCategory CategorizeString(string value)
        {
            // URL patterns
            if (Regex.IsMatch(value, @"^https?://", RegexOptions.IgnoreCase) ||
                Regex.IsMatch(value, @"^ftps?://", RegexOptions.IgnoreCase))
                return StringCategory.Url;

            // IP Address
            if (Regex.IsMatch(value, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"))
                return StringCategory.IpAddress;

            // Email
            if (Regex.IsMatch(value, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
                return StringCategory.Email;

            // Registry key
            if (Regex.IsMatch(value, @"^HK(EY_)?(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)", RegexOptions.IgnoreCase) ||
                value.Contains(@"Software\Microsoft\Windows", StringComparison.OrdinalIgnoreCase))
                return StringCategory.RegistryKey;

            // File path
            if (Regex.IsMatch(value, @"^[A-Za-z]:\\") ||
                Regex.IsMatch(value, @"^\\\\") ||
                value.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase) ||
                value.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase) ||
                value.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase))
                return StringCategory.FilePath;

            // Command
            if (Regex.IsMatch(value, @"^(cmd|powershell|bash|sh)\s", RegexOptions.IgnoreCase))
                return StringCategory.Command;

            return StringCategory.Other;
        }

        private bool IsSuspicious(string value, StringCategory category)
        {
            var suspiciousPatterns = new[]
            {
                // Commands
                "cmd.exe", "powershell", "wscript", "cscript", "mshta",
                
                // Network
                "WinExec", "ShellExecute", "CreateProcess",
                
                // Persistence
                "\\Run", "\\RunOnce", "\\Startup",
                "schtasks", "at.exe",
                
                // Anti-analysis
                "IsDebuggerPresent", "CheckRemoteDebugger", "VirtualBox", "VMware", "QEMU",
                "sample", "virus", "sandbox", "malware",
                
                // Crypto/Encoding
                "base64", "encrypt", "decrypt", "cipher",
                
                // Suspicious extensions
                ".vbs", ".bat", ".ps1", ".exe", ".dll", ".scr",
                
                // C2 indicators
                "beacon", "c2", "cnc", "command", "control",
                
                // Data exfiltration
                "upload", "download", "exfil", "POST", "GET",
                
                // Credentials
                "password", "passwd", "pwd", "credential", "token", "api_key"
            };

            string lower = value.ToLower();
            
            // Check patterns
            if (suspiciousPatterns.Any(pattern => lower.Contains(pattern.ToLower())))
                return true;

            // Suspicious URLs
            if (category == StringCategory.Url)
            {
                if (value.Contains("://", StringComparison.OrdinalIgnoreCase))
                {
                    var suspiciousDomains = new[] { ".tk", ".ml", ".ga", ".cf", ".gq", ".ru", ".cn" };
                    if (suspiciousDomains.Any(domain => lower.EndsWith(domain)))
                        return true;
                }
            }

            // Suspicious registry keys
            if (category == StringCategory.RegistryKey)
            {
                if (lower.Contains("\\run") || lower.Contains("\\startup"))
                    return true;
            }

            // High entropy strings (possible encoded data)
            if (value.Length > 20)
            {
                var entropy = new EntropyCalculator().Calculate(Encoding.ASCII.GetBytes(value));
                if (entropy > 4.5)
                    return true;
            }

            return false;
        }

        public string GenerateReport(ExtractedStrings strings, int maxDisplay = 100)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== STRING EXTRACTION REPORT ===\n");

            sb.AppendLine($"Total ASCII Strings: {strings.AsciiStrings.Count}");
            sb.AppendLine($"Total Unicode Strings: {strings.UnicodeStrings.Count}");
            sb.AppendLine($"Total Suspicious: {strings.SuspiciousStrings.Count}\n");

            if (strings.SuspiciousStrings.Count > 0)
            {
                sb.AppendLine($"⚠ SUSPICIOUS STRINGS ({Math.Min(strings.SuspiciousStrings.Count, maxDisplay)}):");
                foreach (var str in strings.SuspiciousStrings.Take(maxDisplay))
                {
                    sb.AppendLine($"  [{str.Category}] 0x{str.Offset:X8}: {Truncate(str.Value, 80)}");
                }
                if (strings.SuspiciousStrings.Count > maxDisplay)
                    sb.AppendLine($"  ... and {strings.SuspiciousStrings.Count - maxDisplay} more\n");
                sb.AppendLine();
            }

            if (strings.Urls.Count > 0)
            {
                sb.AppendLine($"URLs ({strings.Urls.Count}):");
                foreach (var url in strings.Urls.Take(20))
                    sb.AppendLine($"  - {url.Value}");
                if (strings.Urls.Count > 20)
                    sb.AppendLine($"  ... and {strings.Urls.Count - 20} more");
                sb.AppendLine();
            }

            if (strings.IpAddresses.Count > 0)
            {
                sb.AppendLine($"IP Addresses ({strings.IpAddresses.Count}):");
                foreach (var ip in strings.IpAddresses)
                    sb.AppendLine($"  - {ip.Value}");
                sb.AppendLine();
            }

            if (strings.FilePaths.Count > 0)
            {
                sb.AppendLine($"File Paths ({Math.Min(strings.FilePaths.Count, 20)}):");
                foreach (var path in strings.FilePaths.Take(20))
                    sb.AppendLine($"  - {path.Value}");
                if (strings.FilePaths.Count > 20)
                    sb.AppendLine($"  ... and {strings.FilePaths.Count - 20} more");
                sb.AppendLine();
            }

            if (strings.RegistryKeys.Count > 0)
            {
                sb.AppendLine($"Registry Keys ({strings.RegistryKeys.Count}):");
                foreach (var key in strings.RegistryKeys)
                    sb.AppendLine($"  - {key.Value}");
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private string Truncate(string value, int maxLength)
        {
            if (value.Length <= maxLength)
                return value;
            return value.Substring(0, maxLength - 3) + "...";
        }
    }

    public class ExtractedStrings
    {
        public List<ExtractedString> AsciiStrings { get; set; } = new();
        public List<ExtractedString> UnicodeStrings { get; set; } = new();
        public List<ExtractedString> Urls { get; set; } = new();
        public List<ExtractedString> FilePaths { get; set; } = new();
        public List<ExtractedString> RegistryKeys { get; set; } = new();
        public List<ExtractedString> IpAddresses { get; set; } = new();
        public List<ExtractedString> Emails { get; set; } = new();
        public List<ExtractedString> SuspiciousStrings { get; set; } = new();
    }

    public class ExtractedString
    {
        public string Value { get; set; } = string.Empty;
        public int Offset { get; set; }
        public StringType Type { get; set; }
        public string Encoding { get; set; } = string.Empty;
        public StringCategory Category { get; set; }
        public bool IsSuspicious { get; set; }
    }

    public enum StringType
    {
        Ascii,
        Unicode
    }

    public enum StringCategory
    {
        Other,
        Url,
        IpAddress,
        Email,
        FilePath,
        RegistryKey,
        Command
    }
}