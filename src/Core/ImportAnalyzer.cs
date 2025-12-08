using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PEye.Core
{
    public class ImportAnalyzer
    {
        private readonly PEParser _peParser;
        private readonly byte[] _fileBytes;

        public ImportAnalyzer(PEParser peParser)
        {
            _peParser = peParser;
            _fileBytes = peParser.GetFileBytes();
        }

        public List<ImportedLibrary> ParseImports()
        {
            var imports = new List<ImportedLibrary>();

            if (_peParser.Header == null || !_peParser.IsPE)
                return imports;

            uint importDirectoryRVA = GetImportDirectoryRVA();
            if (importDirectoryRVA == 0)
                return imports;

            uint importDirectoryOffset = _peParser.RvaToFileOffset(importDirectoryRVA);

            int currentOffset = (int)importDirectoryOffset;

            while (true)
            {
                // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes
                if (currentOffset + 20 > _fileBytes.Length)
                    break;

                uint originalFirstThunk = BitConverter.ToUInt32(_fileBytes, currentOffset);
                uint timeDateStamp = BitConverter.ToUInt32(_fileBytes, currentOffset + 4);
                uint forwarderChain = BitConverter.ToUInt32(_fileBytes, currentOffset + 8);
                uint nameRVA = BitConverter.ToUInt32(_fileBytes, currentOffset + 12);
                uint firstThunk = BitConverter.ToUInt32(_fileBytes, currentOffset + 16);

                // End of import table
                if (nameRVA == 0)
                    break;

                string libraryName = ReadStringAtRVA(nameRVA);
                var functions = ParseImportedFunctions(originalFirstThunk != 0 ? originalFirstThunk : firstThunk);

                imports.Add(new ImportedLibrary
                {
                    Name = libraryName,
                    Functions = functions
                });

                currentOffset += 20;
            }

            return imports;
        }

        private List<ImportedFunction> ParseImportedFunctions(uint thunkRVA)
        {
            var functions = new List<ImportedFunction>();
            uint thunkOffset = _peParser.RvaToFileOffset(thunkRVA);

            int currentOffset = (int)thunkOffset;
            int thunkSize = _peParser.Is64Bit ? 8 : 4;

            while (true)
            {
                if (currentOffset + thunkSize > _fileBytes.Length)
                    break;

                ulong thunkValue = _peParser.Is64Bit
                    ? BitConverter.ToUInt64(_fileBytes, currentOffset)
                    : BitConverter.ToUInt32(_fileBytes, currentOffset);

                if (thunkValue == 0)
                    break;

                bool importByOrdinal = _peParser.Is64Bit
                    ? (thunkValue & 0x8000000000000000UL) != 0
                    : (thunkValue & 0x80000000UL) != 0;

                if (importByOrdinal)
                {
                    ushort ordinal = (ushort)(thunkValue & 0xFFFF);
                    functions.Add(new ImportedFunction
                    {
                        Ordinal = ordinal,
                        IsOrdinal = true,
                        Name = $"Ordinal_{ordinal}"
                    });
                }
                else
                {
                    uint nameRVA = (uint)(thunkValue & (_peParser.Is64Bit ? 0x7FFFFFFFFFFFFFFFUL : 0x7FFFFFFFUL));
                    uint nameOffset = _peParser.RvaToFileOffset(nameRVA);

                    if (nameOffset + 2 < _fileBytes.Length)
                    {
                        ushort hint = BitConverter.ToUInt16(_fileBytes, (int)nameOffset);
                        string functionName = ReadStringAt((int)nameOffset + 2);

                        functions.Add(new ImportedFunction
                        {
                            Name = functionName,
                            Hint = hint,
                            IsOrdinal = false
                        });
                    }
                }

                currentOffset += thunkSize;
            }

            return functions;
        }

        private uint GetImportDirectoryRVA()
        {
            if (_peParser.Header == null)
                return 0;

            int dataDirectoryOffset = _peParser.Header.OptionalHeaderOffset + (_peParser.Is64Bit ? 112 : 96);

            // Import Directory is the 2nd entry (index 1)
            int importDirOffset = dataDirectoryOffset + (1 * 8);

            if (importDirOffset + 4 > _fileBytes.Length)
                return 0;

            return BitConverter.ToUInt32(_fileBytes, importDirOffset);
        }

        private string ReadStringAtRVA(uint rva)
        {
            uint offset = _peParser.RvaToFileOffset(rva);
            return ReadStringAt((int)offset);
        }

        private string ReadStringAt(int offset)
        {
            var sb = new StringBuilder();
            while (offset < _fileBytes.Length && _fileBytes[offset] != 0)
            {
                sb.Append((char)_fileBytes[offset]);
                offset++;
            }
            return sb.ToString();
        }

        public ImportAnalysisResult AnalyzeImports(List<ImportedLibrary> imports)
        {
            var result = new ImportAnalysisResult
            {
                TotalLibraries = imports.Count,
                TotalFunctions = imports.Sum(lib => lib.Functions.Count),
                SuspiciousFunctions = new List<string>(),
                RiskLevel = RiskLevel.Low
            };

            var suspiciousAPIs = GetSuspiciousAPIPatterns();

            foreach (var library in imports)
            {
                foreach (var function in library.Functions)
                {
                    string fullName = $"{library.Name}!{function.Name}";
                    
                    foreach (var pattern in suspiciousAPIs)
                    {
                        if (function.Name.Contains(pattern.Key, StringComparison.OrdinalIgnoreCase))
                        {
                            result.SuspiciousFunctions.Add($"{fullName} - {pattern.Value}");
                            result.RiskLevel = (RiskLevel)Math.Max((int)result.RiskLevel, (int)pattern.Value.Risk);
                        }
                    }
                }
            }

            return result;
        }

        private Dictionary<string, SuspiciousAPI> GetSuspiciousAPIPatterns()
        {
            return new Dictionary<string, SuspiciousAPI>(StringComparer.OrdinalIgnoreCase)
            {
                // Process manipulation
                { "CreateRemoteThread", new SuspiciousAPI("Process injection", RiskLevel.Critical) },
                { "WriteProcessMemory", new SuspiciousAPI("Memory manipulation", RiskLevel.High) },
                { "VirtualAllocEx", new SuspiciousAPI("Remote memory allocation", RiskLevel.High) },
                { "SetThreadContext", new SuspiciousAPI("Thread hijacking", RiskLevel.Critical) },
                { "QueueUserAPC", new SuspiciousAPI("APC injection", RiskLevel.High) },
                
                // Keylogging
                { "SetWindowsHookEx", new SuspiciousAPI("Keyboard/mouse hooking", RiskLevel.High) },
                { "GetAsyncKeyState", new SuspiciousAPI("Keylogging", RiskLevel.Medium) },
                { "GetForegroundWindow", new SuspiciousAPI("Window monitoring", RiskLevel.Low) },
                
                // Network
                { "InternetOpen", new SuspiciousAPI("Network communication", RiskLevel.Medium) },
                { "InternetConnect", new SuspiciousAPI("Network connection", RiskLevel.Medium) },
                { "URLDownloadToFile", new SuspiciousAPI("File download", RiskLevel.Medium) },
                { "WSAStartup", new SuspiciousAPI("Network sockets", RiskLevel.Low) },
                
                // Crypto
                { "CryptAcquireContext", new SuspiciousAPI("Cryptography", RiskLevel.Medium) },
                { "CryptEncrypt", new SuspiciousAPI("Encryption", RiskLevel.Medium) },
                { "CryptDecrypt", new SuspiciousAPI("Decryption", RiskLevel.Medium) },
                
                // Registry
                { "RegSetValueEx", new SuspiciousAPI("Registry modification", RiskLevel.Medium) },
                { "RegCreateKeyEx", new SuspiciousAPI("Registry key creation", RiskLevel.Medium) },
                { "RegDeleteKey", new SuspiciousAPI("Registry deletion", RiskLevel.Medium) },
                
                // File operations
                { "CreateFile", new SuspiciousAPI("File access", RiskLevel.Low) },
                { "DeleteFile", new SuspiciousAPI("File deletion", RiskLevel.Low) },
                { "MoveFile", new SuspiciousAPI("File movement", RiskLevel.Low) },
                
                // Anti-analysis
                { "IsDebuggerPresent", new SuspiciousAPI("Debugger detection", RiskLevel.High) },
                { "CheckRemoteDebuggerPresent", new SuspiciousAPI("Remote debugger detection", RiskLevel.High) },
                { "GetTickCount", new SuspiciousAPI("Timing check (anti-debug)", RiskLevel.Medium) },
                { "OutputDebugString", new SuspiciousAPI("Debug output", RiskLevel.Low) },
                
                // Service/Driver
                { "CreateService", new SuspiciousAPI("Service creation", RiskLevel.High) },
                { "StartService", new SuspiciousAPI("Service start", RiskLevel.Medium) },
                { "OpenSCManager", new SuspiciousAPI("Service manager access", RiskLevel.Medium) },
            };
        }

        public string GenerateReport(List<ImportedLibrary> imports, ImportAnalysisResult analysis)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== IMPORT ANALYSIS REPORT ===\n");
            sb.AppendLine($"Total Libraries: {analysis.TotalLibraries}");
            sb.AppendLine($"Total Functions: {analysis.TotalFunctions}");
            sb.AppendLine($"Risk Level: {analysis.RiskLevel}\n");

            if (analysis.SuspiciousFunctions.Count > 0)
            {
                sb.AppendLine($"Suspicious Functions ({analysis.SuspiciousFunctions.Count}):");
                foreach (var func in analysis.SuspiciousFunctions)
                {
                    sb.AppendLine($"  ⚠ {func}");
                }
                sb.AppendLine();
            }

            sb.AppendLine("Imported Libraries:");
            foreach (var library in imports)
            {
                sb.AppendLine($"\n[{library.Name}] ({library.Functions.Count} functions)");
                foreach (var function in library.Functions.Take(50)) // Limit display
                {
                    if (function.IsOrdinal)
                        sb.AppendLine($"  - {function.Name}");
                    else
                        sb.AppendLine($"  - {function.Name} (Hint: {function.Hint})");
                }

                if (library.Functions.Count > 50)
                    sb.AppendLine($"  ... and {library.Functions.Count - 50} more");
            }

            return sb.ToString();
        }
    }

    public class ImportedLibrary
    {
        public string Name { get; set; } = string.Empty;
        public List<ImportedFunction> Functions { get; set; } = new List<ImportedFunction>();
    }

    public class ImportedFunction
    {
        public string Name { get; set; } = string.Empty;
        public ushort Hint { get; set; }
        public ushort Ordinal { get; set; }
        public bool IsOrdinal { get; set; }
    }

    public class ImportAnalysisResult
    {
        public int TotalLibraries { get; set; }
        public int TotalFunctions { get; set; }
        public List<string> SuspiciousFunctions { get; set; } = new List<string>();
        public RiskLevel RiskLevel { get; set; }
    }

    public class SuspiciousAPI
    {
        public string Description { get; set; }
        public RiskLevel Risk { get; set; }

        public SuspiciousAPI(string description, RiskLevel risk)
        {
            Description = description;
            Risk = risk;
        }
    }

    public enum RiskLevel
    {
        Low,
        Medium,
        High,
        Critical
    }
}