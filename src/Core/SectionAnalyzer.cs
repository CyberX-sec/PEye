using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PEye.Core
{
    public class SectionAnalyzer
    {
        private readonly PEParser _peParser;
        private readonly EntropyCalculator _entropyCalculator;

        public SectionAnalyzer(PEParser peParser)
        {
            _peParser = peParser;
            _entropyCalculator = new EntropyCalculator();
        }

        public List<SectionAnalysisResult> AnalyzeAllSections()
        {
            var results = new List<SectionAnalysisResult>();

            if (_peParser.Header?.Sections == null)
                return results;

            foreach (var section in _peParser.Header.Sections)
            {
                results.Add(AnalyzeSection(section));
            }

            return results;
        }

        public SectionAnalysisResult AnalyzeSection(SectionHeader section)
        {
            var result = new SectionAnalysisResult
            {
                Name = section.Name,
                VirtualAddress = section.VirtualAddress,
                VirtualSize = section.VirtualSize,
                RawSize = section.SizeOfRawData,
                IsExecutable = section.IsExecutable,
                IsWritable = section.IsWritable,
                IsReadable = section.IsReadable
            };

            // Get section data
            byte[] sectionData = _peParser.GetSectionData(section);
            
            // Calculate entropy
            result.Entropy = _entropyCalculator.Calculate(sectionData);

            // Detect anomalies
            result.Anomalies = DetectAnomalies(section, sectionData, result.Entropy);

            // Check for suspicious characteristics
            result.IsSuspicious = IsSectionSuspicious(section, result);

            return result;
        }

        private List<string> DetectAnomalies(SectionHeader section, byte[] data, double entropy)
        {
            var anomalies = new List<string>();

            // High entropy suggests encryption/packing
            if (entropy > 7.0)
            {
                anomalies.Add($"High entropy ({entropy:F2}) - possibly packed/encrypted");
            }

            // Executable and writable is suspicious
            if (section.IsExecutable && section.IsWritable)
            {
                anomalies.Add("Section is both executable and writable (RWX)");
            }

            // Size mismatch
            if (section.VirtualSize > 0 && section.SizeOfRawData > 0)
            {
                double ratio = (double)section.VirtualSize / section.SizeOfRawData;
                if (ratio > 2.0 || ratio < 0.5)
                {
                    anomalies.Add($"Virtual/Raw size mismatch (ratio: {ratio:F2})");
                }
            }

            // Unusual section name
            if (!IsStandardSectionName(section.Name))
            {
                anomalies.Add($"Non-standard section name: {section.Name}");
            }

            // Check for null bytes ratio
            int nullBytes = data.Count(b => b == 0);
            double nullRatio = (double)nullBytes / data.Length;
            if (nullRatio > 0.9)
            {
                anomalies.Add($"Very high null byte ratio ({nullRatio:P})");
            }

            return anomalies;
        }

        private bool IsSectionSuspicious(SectionHeader section, SectionAnalysisResult result)
        {
            // Multiple criteria for suspicion
            int suspicionScore = 0;

            if (result.Entropy > 7.0) suspicionScore += 2;
            if (section.IsExecutable && section.IsWritable) suspicionScore += 3;
            if (!IsStandardSectionName(section.Name)) suspicionScore += 1;
            if (result.Anomalies.Count > 2) suspicionScore += 2;

            return suspicionScore >= 3;
        }

        private bool IsStandardSectionName(string name)
        {
            string[] standardNames = 
            {
                ".text", ".data", ".rdata", ".bss", ".idata", 
                ".edata", ".rsrc", ".reloc", ".tls", ".debug",
                "CODE", "DATA", "BSS", "INIT"
            };

            return standardNames.Contains(name, StringComparer.OrdinalIgnoreCase) ||
                   standardNames.Any(std => name.StartsWith(std, StringComparison.OrdinalIgnoreCase));
        }

        public string GenerateReport(List<SectionAnalysisResult> results)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== SECTION ANALYSIS REPORT ===\n");

            foreach (var result in results)
            {
                sb.AppendLine($"Section: {result.Name}");
                sb.AppendLine($"  Virtual Address: 0x{result.VirtualAddress:X8}");
                sb.AppendLine($"  Virtual Size: 0x{result.VirtualSize:X8} ({result.VirtualSize} bytes)");
                sb.AppendLine($"  Raw Size: 0x{result.RawSize:X8} ({result.RawSize} bytes)");
                sb.AppendLine($"  Permissions: {(result.IsReadable ? "R" : "-")}{(result.IsWritable ? "W" : "-")}{(result.IsExecutable ? "X" : "-")}");
                sb.AppendLine($"  Entropy: {result.Entropy:F4}");
                sb.AppendLine($"  Suspicious: {(result.IsSuspicious ? "YES" : "NO")}");

                if (result.Anomalies.Count > 0)
                {
                    sb.AppendLine("  Anomalies:");
                    foreach (var anomaly in result.Anomalies)
                    {
                        sb.AppendLine($"    - {anomaly}");
                    }
                }

                sb.AppendLine();
            }

            return sb.ToString();
        }
    }

    public class SectionAnalysisResult
    {
        public string Name { get; set; } = string.Empty;
        public uint VirtualAddress { get; set; }
        public uint VirtualSize { get; set; }
        public uint RawSize { get; set; }
        public bool IsExecutable { get; set; }
        public bool IsWritable { get; set; }
        public bool IsReadable { get; set; }
        public double Entropy { get; set; }
        public bool IsSuspicious { get; set; }
        public List<string> Anomalies { get; set; } = new List<string>();
    }
}