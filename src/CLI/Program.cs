using System;
using System.IO;
using System.Linq;
using System.Text;
using PEye.Core;
using PEye.Utils;

namespace PEye.CLI
{
    class Program
    {
        static void Main(string[] args)
        {
            Helpers.PrintBanner();

            if (args.Length == 0)
            {
                PrintUsage();
                return;
            }

            string filePath = args[0];
            bool recursive = Array.Exists(args, arg => arg == "-R" || arg == "--recursive");
            bool generateReport = args.Length > 1 && (args[1] == "--report" || args[1] == "-r");
            bool verbose = Array.Exists(args, arg => arg == "-v" || arg == "--verbose");
            string? outputPath = null;

            // Parse output path
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == "-o" || args[i] == "--output")
                {
                    outputPath = args[i + 1];
                    break;
                }
            }

            if (!File.Exists(filePath))
            {
                Helpers.PrintError($"File not found: {filePath}");
                return;
            }

            if (!FileUtils.IsPEFile(filePath))
            {
                Helpers.PrintError("File is not a valid PE file");
                return;
            }

            try
            {
                // If user passed a directory, analyze all files inside
                if (Directory.Exists(filePath))
                {
                    var searchOption = recursive ? System.IO.SearchOption.AllDirectories : System.IO.SearchOption.TopDirectoryOnly;
                    var files = Directory.GetFiles(filePath, "*", searchOption);

                    var combinedReport = new StringBuilder();
                    var runStart = DateTime.UtcNow;

                    foreach (var f in files)
                    {
                        if (!File.Exists(f))
                            continue;

                        if (!FileUtils.IsPEFile(f))
                        {
                            if (verbose)
                                Helpers.PrintInfo($"Skipping non-PE file: {f}");
                            continue;
                        }

                        var report = AnalyzeSingleFile(f, verbose);
                        combinedReport.AppendLine(report);
                    }

                    // Save combined report if requested
                    if (generateReport)
                    {
                        string outPath = outputPath ?? Path.Combine(Directory.GetCurrentDirectory(), $"directory_analysis_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                        // If outputPath looks like a directory, make it a file inside that dir
                        if (outputPath != null && Directory.Exists(outputPath))
                        {
                            outPath = Path.Combine(outputPath, $"directory_analysis_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                        }

                        SaveReport("directory", combinedReport.ToString(), outPath);
                    }
                }
                else
                {
                    AnalyzeFile(filePath, generateReport, verbose, outputPath);
                }
            }
            catch (Exception ex)
            {
                Helpers.PrintError($"Analysis failed: {ex.Message}");
                if (verbose)
                {
                    Console.WriteLine(ex.StackTrace);
                }
            }
        }

        // New helper that runs the analysis for a single file and returns the full textual report.
        static string AnalyzeSingleFile(string filePath, bool verbose)
        {
            var analysisStart = DateTime.UtcNow;
            var fileName = Path.GetFileName(filePath);
            var reportBuilder = new StringBuilder();

            Helpers.PrintInfo($"Analyzing: {fileName}");
            Helpers.PrintInfo($"File Type: {FileUtils.GetFileType(filePath)}");
            Helpers.PrintInfo($"File Size: {FileUtils.FormatBytes(new FileInfo(filePath).Length)}\n");

            // Generate report header
            reportBuilder.Append(Helpers.GenerateReportHeader(fileName, analysisStart));

            // Step 1: Calculate Hashes
            Helpers.PrintSection("HASH CALCULATION");
            var hashes = Hashing.CalculateHashes(filePath);
            string hashReport = Hashing.GenerateReport(hashes);
            Console.WriteLine(hashReport);
            reportBuilder.AppendLine(hashReport);

            // Step 2: Parse PE Structure
            Helpers.PrintSection("PE STRUCTURE ANALYSIS");
            var peParser = new PEParser(filePath);

            if (!peParser.IsPE)
            {
                Helpers.PrintError("Invalid PE file structure");
                return reportBuilder.ToString();
            }

            // reuse existing PrintPEInfo which appends to reportBuilder as well
            PrintPEInfo(peParser, reportBuilder);

            // Step 3: Section Analysis
            Helpers.PrintSection("SECTION ANALYSIS");
            var sectionAnalyzer = new SectionAnalyzer(peParser);
            var sectionResults = sectionAnalyzer.AnalyzeAllSections();
            string sectionReport = sectionAnalyzer.GenerateReport(sectionResults);
            Console.WriteLine(sectionReport);
            reportBuilder.AppendLine(sectionReport);

            if (sectionResults.Any(s => s.IsSuspicious))
            {
                Helpers.PrintWarning($"{sectionResults.Count(s => s.IsSuspicious)} suspicious section(s) detected!");
            }

            // Step 4: Import Analysis
            Helpers.PrintSection("IMPORT ANALYSIS");
            var importAnalyzer = new ImportAnalyzer(peParser);
            var imports = importAnalyzer.ParseImports();
            var importAnalysis = importAnalyzer.AnalyzeImports(imports);
            string importReport = importAnalyzer.GenerateReport(imports, importAnalysis);
            Console.WriteLine(importReport);
            reportBuilder.AppendLine(importReport);

            if (importAnalysis.RiskLevel >= RiskLevel.High)
            {
                Helpers.PrintWarning($"High-risk imports detected! Risk Level: {importAnalysis.RiskLevel}");
            }

            // Step 5: String Extraction
            Helpers.PrintSection("STRING EXTRACTION");
            var stringExtractor = new StringExtractor();
            var fileBytes = File.ReadAllBytes(filePath);
            var extractedStrings = stringExtractor.Extract(fileBytes);
            string stringReport = stringExtractor.GenerateReport(extractedStrings);
            Console.WriteLine(stringReport);
            reportBuilder.AppendLine(stringReport);

            if (extractedStrings.SuspiciousStrings.Count > 0)
            {
                Helpers.PrintWarning($"{extractedStrings.SuspiciousStrings.Count} suspicious string(s) found!");
            }

            // Step 6: Decoder Engine
            Helpers.PrintSection("ENCODED STRING DETECTION");
            var decoder = new DecoderEngine();
            var decodingResult = decoder.DecodeAll(fileBytes);
            string decoderReport = decoder.GenerateReport(decodingResult);
            Console.WriteLine(decoderReport);
            reportBuilder.AppendLine(decoderReport);

            if (decodingResult.TotalDecoded > 0)
            {
                Helpers.PrintWarning($"{decodingResult.TotalDecoded} potentially encoded string(s) decoded!");
            }

            // Step 7: Resource Analysis
            Helpers.PrintSection("RESOURCE ANALYSIS");
            var resourceParser = new ResourceParser(peParser);
            var resources = resourceParser.ParseResources();
            var resourceAnalysis = resourceParser.AnalyzeResources(resources);
            string resourceReport = resourceParser.GenerateReport(resources, resourceAnalysis);
            Console.WriteLine(resourceReport);
            reportBuilder.AppendLine(resourceReport);

            if (resourceAnalysis.SuspiciousResources.Count > 0)
            {
                Helpers.PrintWarning($"{resourceAnalysis.SuspiciousResources.Count} suspicious resource(s) detected!");
            }

            // Step 8: Packer Detection
            Helpers.PrintSection("PACKER DETECTION");
            var packerDetector = new PackerDetector(peParser);
            var packerResult = packerDetector.Detect();
            string packerReport = packerDetector.GenerateReport(packerResult);
            Console.WriteLine(packerReport);
            reportBuilder.AppendLine(packerReport);

            if (packerResult.IsPacked)
            {
                Helpers.PrintWarning("File appears to be PACKED!");
            }

            // Final Summary
            Helpers.PrintSection("ANALYSIS SUMMARY");
            PrintSummary(peParser, sectionResults, importAnalysis, extractedStrings,
                        decodingResult, resourceAnalysis, packerResult, reportBuilder);

            reportBuilder.Append(Helpers.GenerateReportFooter());

            var analysisEnd = DateTime.UtcNow;
            var duration = analysisEnd - analysisStart;
            Helpers.PrintSuccess($"\nAnalysis completed in {duration.TotalSeconds:F02} seconds");

            return reportBuilder.ToString();
        }

        static void AnalyzeFile(string filePath, bool generateReport, bool verbose, string? outputPath)
        {
            var analysisStart = DateTime.UtcNow;
            var fileName = Path.GetFileName(filePath);
            var reportBuilder = new StringBuilder();

            Helpers.PrintInfo($"Analyzing: {fileName}");
            Helpers.PrintInfo($"File Type: {FileUtils.GetFileType(filePath)}");
            Helpers.PrintInfo($"File Size: {FileUtils.FormatBytes(new FileInfo(filePath).Length)}\n");

            // Generate report header
            reportBuilder.Append(Helpers.GenerateReportHeader(fileName, analysisStart));

            // Step 1: Calculate Hashes
            Helpers.PrintSection("HASH CALCULATION");
            var hashes = Hashing.CalculateHashes(filePath);
            string hashReport = Hashing.GenerateReport(hashes);
            Console.WriteLine(hashReport);
            reportBuilder.AppendLine(hashReport);

            // Step 2: Parse PE Structure
            Helpers.PrintSection("PE STRUCTURE ANALYSIS");
            var peParser = new PEParser(filePath);
            
            if (!peParser.IsPE)
            {
                Helpers.PrintError("Invalid PE file structure");
                return;
            }

            PrintPEInfo(peParser, reportBuilder);

            // Step 3: Section Analysis
            Helpers.PrintSection("SECTION ANALYSIS");
            var sectionAnalyzer = new SectionAnalyzer(peParser);
            var sectionResults = sectionAnalyzer.AnalyzeAllSections();
            string sectionReport = sectionAnalyzer.GenerateReport(sectionResults);
            Console.WriteLine(sectionReport);
            reportBuilder.AppendLine(sectionReport);

            if (sectionResults.Any(s => s.IsSuspicious))
            {
                Helpers.PrintWarning($"{sectionResults.Count(s => s.IsSuspicious)} suspicious section(s) detected!");
            }

            // Step 4: Import Analysis
            Helpers.PrintSection("IMPORT ANALYSIS");
            var importAnalyzer = new ImportAnalyzer(peParser);
            var imports = importAnalyzer.ParseImports();
            var importAnalysis = importAnalyzer.AnalyzeImports(imports);
            string importReport = importAnalyzer.GenerateReport(imports, importAnalysis);
            Console.WriteLine(importReport);
            reportBuilder.AppendLine(importReport);

            if (importAnalysis.RiskLevel >= RiskLevel.High)
            {
                Helpers.PrintWarning($"High-risk imports detected! Risk Level: {importAnalysis.RiskLevel}");
            }

            // Step 5: String Extraction
            Helpers.PrintSection("STRING EXTRACTION");
            var stringExtractor = new StringExtractor();
            var fileBytes = File.ReadAllBytes(filePath);
            var extractedStrings = stringExtractor.Extract(fileBytes);
            string stringReport = stringExtractor.GenerateReport(extractedStrings);
            Console.WriteLine(stringReport);
            reportBuilder.AppendLine(stringReport);

            if (extractedStrings.SuspiciousStrings.Count > 0)
            {
                Helpers.PrintWarning($"{extractedStrings.SuspiciousStrings.Count} suspicious string(s) found!");
            }

            // Step 6: Decoder Engine
            Helpers.PrintSection("ENCODED STRING DETECTION");
            var decoder = new DecoderEngine();
            var decodingResult = decoder.DecodeAll(fileBytes);
            string decoderReport = decoder.GenerateReport(decodingResult);
            Console.WriteLine(decoderReport);
            reportBuilder.AppendLine(decoderReport);

            if (decodingResult.TotalDecoded > 0)
            {
                Helpers.PrintWarning($"{decodingResult.TotalDecoded} potentially encoded string(s) decoded!");
            }

            // Step 7: Resource Analysis
            Helpers.PrintSection("RESOURCE ANALYSIS");
            var resourceParser = new ResourceParser(peParser);
            var resources = resourceParser.ParseResources();
            var resourceAnalysis = resourceParser.AnalyzeResources(resources);
            string resourceReport = resourceParser.GenerateReport(resources, resourceAnalysis);
            Console.WriteLine(resourceReport);
            reportBuilder.AppendLine(resourceReport);

            if (resourceAnalysis.SuspiciousResources.Count > 0)
            {
                Helpers.PrintWarning($"{resourceAnalysis.SuspiciousResources.Count} suspicious resource(s) detected!");
            }

            // Step 8: Packer Detection
            Helpers.PrintSection("PACKER DETECTION");
            var packerDetector = new PackerDetector(peParser);
            var packerResult = packerDetector.Detect();
            string packerReport = packerDetector.GenerateReport(packerResult);
            Console.WriteLine(packerReport);
            reportBuilder.AppendLine(packerReport);

            if (packerResult.IsPacked)
            {
                Helpers.PrintWarning("File appears to be PACKED!");
            }

            // Final Summary
            Helpers.PrintSection("ANALYSIS SUMMARY");
            PrintSummary(peParser, sectionResults, importAnalysis, extractedStrings, 
                        decodingResult, resourceAnalysis, packerResult, reportBuilder);

            reportBuilder.Append(Helpers.GenerateReportFooter());

            // Save report if requested
            if (generateReport)
            {
                SaveReport(filePath, reportBuilder.ToString(), outputPath);
            }

            var analysisEnd = DateTime.UtcNow;
            var duration = analysisEnd - analysisStart;
            Helpers.PrintSuccess($"\nAnalysis completed in {duration.TotalSeconds:F2} seconds");
        }

        static void PrintPEInfo(PEParser peParser, StringBuilder reportBuilder)
        {
            if (peParser.Header == null)
                return;

            var sb = new StringBuilder();
            sb.AppendLine("=== PE HEADER INFORMATION ===\n");
            sb.AppendLine($"Architecture:        {(peParser.Is64Bit ? "x64 (64-bit)" : "x86 (32-bit)")}");
            sb.AppendLine($"Machine Type:        0x{peParser.Header.Machine:X4}");
            sb.AppendLine($"Compile Time:        {peParser.Header.GetCompileTime():yyyy-MM-dd HH:mm:ss UTC}");
            sb.AppendLine($"Number of Sections:  {peParser.Header.NumberOfSections}");
            sb.AppendLine($"Entry Point:         0x{peParser.Header.AddressOfEntryPoint:X8}");
            sb.AppendLine($"Image Base:          0x{peParser.Header.ImageBase:X}");
            sb.AppendLine($"Subsystem:           {GetSubsystemName(peParser.Header.Subsystem)}");
            sb.AppendLine($"Checksum:            0x{peParser.Header.CheckSum:X8}");
            sb.AppendLine($"Size of Image:       {FileUtils.FormatBytes(peParser.Header.SizeOfImage)}");
            sb.AppendLine($"Size of Headers:     {FileUtils.FormatBytes(peParser.Header.SizeOfHeaders)}");

            Console.WriteLine(sb.ToString());
            reportBuilder.AppendLine(sb.ToString());
        }

        static void PrintSummary(PEParser peParser, System.Collections.Generic.List<SectionAnalysisResult> sections,
                                ImportAnalysisResult imports, ExtractedStrings strings,
                                DecodingResult decoding, ResourceAnalysisResult resources,
                                PackerDetectionResult packer, StringBuilder reportBuilder)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== THREAT ASSESSMENT ===\n");

            int threatScore = 0;
            var indicators = new System.Collections.Generic.List<string>();

            // Packer detection
            if (packer.IsPacked)
            {
                threatScore += 30;
                indicators.Add($"✗ File is packed ({packer.Confidence:P} confidence)");
            }

            // High-risk imports
            if (imports.RiskLevel == RiskLevel.Critical)
            {
                threatScore += 40;
                indicators.Add($"✗ Critical risk imports detected");
            }
            else if (imports.RiskLevel == RiskLevel.High)
            {
                threatScore += 25;
                indicators.Add($"✗ High risk imports detected");
            }

            // Suspicious sections
            int suspiciousSections = sections.Count(s => s.IsSuspicious);
            if (suspiciousSections > 0)
            {
                threatScore += suspiciousSections * 10;
                indicators.Add($"✗ {suspiciousSections} suspicious section(s)");
            }

            // Suspicious strings
            if (strings.SuspiciousStrings.Count > 10)
            {
                threatScore += 15;
                indicators.Add($"✗ {strings.SuspiciousStrings.Count} suspicious strings found");
            }

            // Encoded strings
            if (decoding.TotalDecoded > 5)
            {
                threatScore += 10;
                indicators.Add($"✗ {decoding.TotalDecoded} potentially encoded strings");
            }

            // Suspicious resources
            if (resources.SuspiciousResources.Count > 0)
            {
                threatScore += 10;
                indicators.Add($"✗ {resources.SuspiciousResources.Count} suspicious resource(s)");
            }

            // High entropy sections
            var highEntropySections = sections.Where(s => s.Entropy > 7.0).ToList();
            if (highEntropySections.Count > 0)
            {
                threatScore += 15;
                indicators.Add($"✗ {highEntropySections.Count} high-entropy section(s)");
            }

            // Determine threat level
            string threatLevel;
            ConsoleColor color;

            if (threatScore >= 70)
            {
                threatLevel = "CRITICAL";
                color = ConsoleColor.Red;
            }
            else if (threatScore >= 50)
            {
                threatLevel = "HIGH";
                color = ConsoleColor.DarkRed;
            }
            else if (threatScore >= 30)
            {
                threatLevel = "MEDIUM";
                color = ConsoleColor.Yellow;
            }
            else if (threatScore >= 10)
            {
                threatLevel = "LOW";
                color = ConsoleColor.DarkYellow;
            }
            else
            {
                threatLevel = "INFORMATIONAL";
                color = ConsoleColor.Green;
            }

            sb.AppendLine($"Threat Score: {threatScore}/100");
            sb.AppendLine($"Threat Level: {threatLevel}\n");

            if (indicators.Count > 0)
            {
                sb.AppendLine("Indicators of Compromise:");
                foreach (var indicator in indicators)
                {
                    sb.AppendLine($"  {indicator}");
                }
            }
            else
            {
                sb.AppendLine("✓ No significant threats detected");
            }

            Console.ForegroundColor = color;
            Console.WriteLine(sb.ToString());
            Console.ResetColor();

            reportBuilder.AppendLine(sb.ToString());
        }

        static void SaveReport(string filePath, string report, string? outputPath)
        {
            try
            {
                string reportFileName;
                
                if (string.IsNullOrEmpty(outputPath))
                {
                    var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    var baseName = Path.GetFileNameWithoutExtension(filePath);
                    reportFileName = $"{baseName}_analysis_{timestamp}.txt";
                }
                else
                {
                    reportFileName = outputPath;
                }

                File.WriteAllText(reportFileName, report);
                Helpers.PrintSuccess($"Report saved to: {reportFileName}");
            }
            catch (Exception ex)
            {
                Helpers.PrintError($"Failed to save report: {ex.Message}");
            }
        }

        static string GetSubsystemName(ushort subsystem)
        {
            return subsystem switch
            {
                1 => "Native",
                2 => "Windows GUI",
                3 => "Windows CUI (Console)",
                5 => "OS/2 CUI",
                7 => "POSIX CUI",
                9 => "Windows CE GUI",
                10 => "EFI Application",
                11 => "EFI Boot Service Driver",
                12 => "EFI Runtime Driver",
                13 => "EFI ROM",
                14 => "XBOX",
                16 => "Windows Boot Application",
                _ => $"Unknown (0x{subsystem:X4})"
            };
        }

        static void PrintUsage()
        {
            Console.WriteLine("Usage: PEye <file> [options]\n");
            Console.WriteLine("Options:");
            Console.WriteLine("  -r, --report              Generate analysis report");
            Console.WriteLine("  -o, --output <path>       Specify output report path");
            Console.WriteLine("  -v, --verbose             Enable verbose output");
            Console.WriteLine("  -h, --help                Show this help message\n");
            Console.WriteLine("Examples:");
            Console.WriteLine("  PEye sample.exe");
            Console.WriteLine("  PEye malware.dll --report");
            Console.WriteLine("  PEye suspicious.exe -r -o report.txt");
            Console.WriteLine("  PEye file.exe --verbose\n");
        }
    }
}