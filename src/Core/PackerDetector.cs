using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PEye.Core
{
    public class PackerDetector
    {
        private readonly PEParser _peParser;
        private readonly byte[] _fileBytes;

        public PackerDetector(PEParser peParser)
        {
            _peParser = peParser;
            _fileBytes = peParser.GetFileBytes();
        }

        public PackerDetectionResult Detect()
        {
            var result = new PackerDetectionResult();

            // Signature-based detection
            result.DetectedPackers.AddRange(DetectBySignature());

            // Heuristic-based detection
            var heuristics = DetectByHeuristics();
            result.Heuristics.AddRange(heuristics);

            // Section-based detection
            result.SectionIndicators.AddRange(DetectBySections());

            // Import table analysis
            result.ImportIndicators.AddRange(DetectByImports());

            // Entry point analysis
            result.EntryPointIndicators.AddRange(DetectByEntryPoint());

            // Determine if packed
            result.IsPacked = result.DetectedPackers.Count > 0 || 
                             result.Heuristics.Count >= 3 ||
                             result.SectionIndicators.Count >= 2;

            result.Confidence = CalculateConfidence(result);

            return result;
        }

        private List<PackerSignature> DetectBySignature()
        {
            var detected = new List<PackerSignature>();
            var signatures = GetPackerSignatures();

            foreach (var signature in signatures)
            {
                if (SearchForSignature(signature.Pattern, signature.Offset))
                {
                    detected.Add(signature);
                }
            }

            return detected;
        }

        private List<string> DetectByHeuristics()
        {
            var indicators = new List<string>();

            if (_peParser.Header == null)
                return indicators;

            // High entropy in code sections
            var entropyCalc = new EntropyCalculator();
            var textSection = _peParser.Header.Sections.FirstOrDefault(s => s.Name.Contains("text"));
            if (textSection != null)
            {
                var sectionData = _peParser.GetSectionData(textSection);
                double entropy = entropyCalc.Calculate(sectionData);
                
                if (entropy > 7.0)
                {
                    indicators.Add($"High entropy in .text section ({entropy:F2}) - likely packed/encrypted");
                }
            }

            // Suspicious section names
            var suspiciousSectionNames = new[] { "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".perplex", ".neolit", "!EPack", ".petite" };
            foreach (var section in _peParser.Header.Sections)
            {
                if (suspiciousSectionNames.Any(name => section.Name.Contains(name, StringComparison.OrdinalIgnoreCase)))
                {
                    indicators.Add($"Suspicious section name: {section.Name}");
                }
            }

            // Raw size vs virtual size discrepancy
            foreach (var section in _peParser.Header.Sections)
            {
                if (section.VirtualSize > 0 && section.SizeOfRawData > 0)
                {
                    double ratio = (double)section.VirtualSize / section.SizeOfRawData;
                    if (ratio > 2.5)
                    {
                        indicators.Add($"Section {section.Name} has large virtual/raw size ratio ({ratio:F2})");
                    }
                }
            }

            // Very few imports
            var importAnalyzer = new ImportAnalyzer(_peParser);
            var imports = importAnalyzer.ParseImports();
            if (imports.Count < 3 && imports.Sum(i => i.Functions.Count) < 10)
            {
                indicators.Add($"Very few imports ({imports.Sum(i => i.Functions.Count)}) - possible import hiding");
            }

            // Entry point in unusual section
            uint entryPoint = _peParser.Header.AddressOfEntryPoint;
            var epSection = _peParser.Header.Sections.FirstOrDefault(s => 
                entryPoint >= s.VirtualAddress && 
                entryPoint < s.VirtualAddress + s.VirtualSize);

            if (epSection != null && !epSection.Name.Contains("text") && !epSection.Name.Contains("code"))
            {
                indicators.Add($"Entry point in unusual section: {epSection.Name}");
            }

            // Suspicious overlay data
            var lastSection = _peParser.Header.Sections.OrderByDescending(s => s.PointerToRawData).FirstOrDefault();
            if (lastSection != null)
            {
                uint expectedEnd = lastSection.PointerToRawData + lastSection.SizeOfRawData;
                if (_fileBytes.Length > expectedEnd + 1024)
                {
                    long overlaySize = _fileBytes.Length - expectedEnd;
                    indicators.Add($"Large overlay data detected ({overlaySize:N0} bytes)");
                }
            }

            return indicators;
        }

        private List<string> DetectBySections()
        {
            var indicators = new List<string>();

            if (_peParser.Header?.Sections == null)
                return indicators;

            // Executable sections with low entropy might contain unpacker stub
            var entropyCalc = new EntropyCalculator();
            foreach (var section in _peParser.Header.Sections.Where(s => s.IsExecutable))
            {
                var data = _peParser.GetSectionData(section);
                double entropy = entropyCalc.Calculate(data);

                if (entropy < 2.0)
                {
                    indicators.Add($"Executable section {section.Name} has very low entropy ({entropy:F2})");
                }
            }

            // Multiple executable sections
            int executableSections = _peParser.Header.Sections.Count(s => s.IsExecutable);
            if (executableSections > 3)
            {
                indicators.Add($"Unusual number of executable sections ({executableSections})");
            }

            // Writable and executable sections
            foreach (var section in _peParser.Header.Sections.Where(s => s.IsExecutable && s.IsWritable))
            {
                indicators.Add($"Section {section.Name} is both writable and executable (RWX)");
            }

            return indicators;
        }

        private List<string> DetectByImports()
        {
            var indicators = new List<string>();
            var importAnalyzer = new ImportAnalyzer(_peParser);
            var imports = importAnalyzer.ParseImports();

            // Packer-related imports
            var packerAPIs = new Dictionary<string, string>
            {
                { "VirtualProtect", "Memory protection change (self-modifying code)" },
                { "VirtualAlloc", "Dynamic memory allocation" },
                { "LoadLibraryA", "Dynamic library loading" },
                { "GetProcAddress", "Dynamic function resolution" },
                { "IsDebuggerPresent", "Anti-debugging" },
                { "CreateThread", "Thread creation (unpacking stub)" }
            };

            int packerAPICount = 0;
            foreach (var library in imports)
            {
                foreach (var function in library.Functions)
                {
                    if (packerAPIs.ContainsKey(function.Name))
                    {
                        packerAPICount++;
                    }
                }
            }

            if (packerAPICount >= 3)
            {
                indicators.Add($"Multiple packer-related APIs detected ({packerAPICount})");
            }

            return indicators;
        }

        private List<string> DetectByEntryPoint()
        {
            var indicators = new List<string>();

            if (_peParser.Header == null)
                return indicators;

            uint ep = _peParser.Header.AddressOfEntryPoint;
            uint epOffset = _peParser.RvaToFileOffset(ep);

            if (epOffset + 16 > _fileBytes.Length)
                return indicators;

            // Read first bytes at entry point
            byte[] epBytes = new byte[16];
            Array.Copy(_fileBytes, epOffset, epBytes, 0, 16);

            // Common packer signatures at entry point
            // UPX: 60 BE ?? ?? ?? ?? 8D BE
            if (epBytes[0] == 0x60 && epBytes[1] == 0xBE && epBytes[6] == 0x8D && epBytes[7] == 0xBE)
            {
                indicators.Add("UPX-like entry point pattern detected");
            }

            // ASPack: 60 E8 ?? ?? ?? ?? 5D 81
            if (epBytes[0] == 0x60 && epBytes[1] == 0xE8 && epBytes[6] == 0x5D && epBytes[7] == 0x81)
            {
                indicators.Add("ASPack-like entry point pattern detected");
            }

            // PUSHAD (60) is common in packers
            if (epBytes[0] == 0x60)
            {
                indicators.Add("PUSHAD instruction at entry point (common packer technique)");
            }

            return indicators;
        }

        private bool SearchForSignature(byte[] pattern, int offset)
        {
            if (offset < 0)
            {
                // Search entire file
                return SearchPattern(pattern, 0, _fileBytes.Length);
            }
            else
            {
                // Search at specific offset
                if (offset + pattern.Length > _fileBytes.Length)
                    return false;

                for (int i = 0; i < pattern.Length; i++)
                {
                    if (pattern[i] != 0xFF && pattern[i] != _fileBytes[offset + i])
                        return false;
                }
                return true;
            }
        }

        private bool SearchPattern(byte[] pattern, int start, int end)
        {
            for (int i = start; i <= end - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (pattern[j] != 0xFF && pattern[j] != _fileBytes[i + j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return true;
            }
            return false;
        }

        private List<PackerSignature> GetPackerSignatures()
        {
            return new List<PackerSignature>
            {
                new PackerSignature 
                { 
                    Name = "UPX", 
                    Pattern = new byte[] { 0x55, 0x50, 0x58, 0x30 }, // "UPX0"
                    Offset = -1 
                },
                new PackerSignature 
                { 
                    Name = "UPX", 
                    Pattern = new byte[] { 0x55, 0x50, 0x58, 0x21 }, // "UPX!"
                    Offset = -1 
                },
                new PackerSignature 
                { 
                    Name = "ASPack", 
                    Pattern = new byte[] { 0x60, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x81 },
                    Offset = -1 
                },
                new PackerSignature 
                { 
                    Name = "PECompact", 
                    Pattern = new byte[] { 0xEB, 0x06, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x9C, 0x60 },
                    Offset = -1 
                },
                new PackerSignature 
                { 
                    Name = "Themida", 
                    Pattern = new byte[] { 0x8B, 0xC0, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D },
                    Offset = -1 
                },
                new PackerSignature 
                { 
                    Name = "VMProtect", 
                    Pattern = new byte[] { 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xE8, 0x01, 0x00, 0x00, 0x00 },
                    Offset = -1 
                },
                new PackerSignature 
                { 
                    Name = "Armadillo", 
                    Pattern = new byte[] { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68 },
                    Offset = -1 
                }
            };
        }

        private double CalculateConfidence(PackerDetectionResult result)
        {
            double confidence = 0.0;

            // Signature matches give high confidence
            if (result.DetectedPackers.Count > 0)
                confidence += 0.6;

            // Multiple heuristics increase confidence
            confidence += Math.Min(result.Heuristics.Count * 0.1, 0.3);

            // Section indicators
            confidence += Math.Min(result.SectionIndicators.Count * 0.05, 0.15);

            return Math.Min(confidence, 1.0);
        }

        public string GenerateReport(PackerDetectionResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== PACKER DETECTION REPORT ===\n");
            sb.AppendLine($"Packed: {(result.IsPacked ? "YES" : "NO")}");
            sb.AppendLine($"Confidence: {result.Confidence:P}\n");

            if (result.DetectedPackers.Count > 0)
            {
                sb.AppendLine("🔒 DETECTED PACKERS:");
                foreach (var packer in result.DetectedPackers)
                {
                    sb.AppendLine($"  - {packer.Name}");
                }
                sb.AppendLine();
            }

            if (result.Heuristics.Count > 0)
            {
                sb.AppendLine("Heuristic Indicators:");
                foreach (var heuristic in result.Heuristics)
                {
                    sb.AppendLine($"  ⚠ {heuristic}");
                }
                sb.AppendLine();
            }

            if (result.SectionIndicators.Count > 0)
            {
                sb.AppendLine("Section Indicators:");
                foreach (var indicator in result.SectionIndicators)
                {
                    sb.AppendLine($"  - {indicator}");
                }
                sb.AppendLine();
            }

            if (result.ImportIndicators.Count > 0)
            {
                sb.AppendLine("Import Indicators:");
                foreach (var indicator in result.ImportIndicators)
                {
                    sb.AppendLine($"  - {indicator}");
                }
                sb.AppendLine();
            }

            if (result.EntryPointIndicators.Count > 0)
            {
                sb.AppendLine("Entry Point Indicators:");
                foreach (var indicator in result.EntryPointIndicators)
                {
                    sb.AppendLine($"  - {indicator}");
                }
            }

            return sb.ToString();
        }
    }

    public class PackerDetectionResult
    {
        public bool IsPacked { get; set; }
        public double Confidence { get; set; }
        public List<PackerSignature> DetectedPackers { get; set; } = new();
        public List<string> Heuristics { get; set; } = new();
        public List<string> SectionIndicators { get; set; } = new();
        public List<string> ImportIndicators { get; set; } = new();
        public List<string> EntryPointIndicators { get; set; } = new();
    }

    public class PackerSignature
    {
        public string Name { get; set; } = string.Empty;
        public byte[] Pattern { get; set; } = Array.Empty<byte>();
        public int Offset { get; set; }
    }
}