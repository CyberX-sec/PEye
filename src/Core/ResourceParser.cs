using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PEye.Core
{
    public class ResourceParser
    {
        private readonly PEParser _peParser;
        private readonly byte[] _fileBytes;

        public ResourceParser(PEParser peParser)
        {
            _peParser = peParser;
            _fileBytes = peParser.GetFileBytes();
        }

        public List<ResourceEntry> ParseResources()
        {
            var resources = new List<ResourceEntry>();

            if (_peParser.Header == null || !_peParser.IsPE)
                return resources;

            uint resourceDirRVA = GetResourceDirectoryRVA();
            if (resourceDirRVA == 0)
                return resources;

            uint resourceDirOffset = _peParser.RvaToFileOffset(resourceDirRVA);
            
            try
            {
                ParseResourceDirectory(resourceDirOffset, resourceDirRVA, resources, "", 0);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error parsing resources: {ex.Message}");
            }

            return resources;
        }

        private void ParseResourceDirectory(uint dirOffset, uint dirRVA, List<ResourceEntry> resources, string path, int level)
        {
            if (level > 3 || dirOffset + 16 > _fileBytes.Length)
                return;

            // IMAGE_RESOURCE_DIRECTORY structure
            ushort numberOfNamedEntries = BitConverter.ToUInt16(_fileBytes, (int)dirOffset + 12);
            ushort numberOfIdEntries = BitConverter.ToUInt16(_fileBytes, (int)dirOffset + 14);

            int totalEntries = numberOfNamedEntries + numberOfIdEntries;
            uint entryOffset = dirOffset + 16;

            for (int i = 0; i < totalEntries && i < 1000; i++)
            {
                if (entryOffset + 8 > _fileBytes.Length)
                    break;

                uint nameOrId = BitConverter.ToUInt32(_fileBytes, (int)entryOffset);
                uint dataOrSubdirOffset = BitConverter.ToUInt32(_fileBytes, (int)entryOffset + 4);

                string entryName = (nameOrId & 0x80000000) != 0
                    ? ReadResourceName(dirOffset, nameOrId & 0x7FFFFFFF)
                    : GetResourceTypeName(nameOrId, level);

                string currentPath = string.IsNullOrEmpty(path) ? entryName : $"{path}/{entryName}";

                bool isDirectory = (dataOrSubdirOffset & 0x80000000) != 0;

                if (isDirectory)
                {
                    uint subdirOffset = dirRVA + (dataOrSubdirOffset & 0x7FFFFFFF);
                    uint subdirFileOffset = _peParser.RvaToFileOffset(subdirOffset);
                    ParseResourceDirectory(subdirFileOffset, dirRVA, resources, currentPath, level + 1);
                }
                else
                {
                    // Resource data entry
                    uint dataEntryOffset = _peParser.RvaToFileOffset(dirRVA + dataOrSubdirOffset);
                    if (dataEntryOffset + 16 <= _fileBytes.Length)
                    {
                        uint dataRVA = BitConverter.ToUInt32(_fileBytes, (int)dataEntryOffset);
                        uint size = BitConverter.ToUInt32(_fileBytes, (int)dataEntryOffset + 4);

                        resources.Add(new ResourceEntry
                        {
                            Path = currentPath,
                            Type = GetResourceType(currentPath),
                            RVA = dataRVA,
                            Size = size,
                            Offset = _peParser.RvaToFileOffset(dataRVA)
                        });
                    }
                }

                entryOffset += 8;
            }
        }

        private string ReadResourceName(uint baseOffset, uint nameOffset)
        {
            try
            {
                uint actualOffset = baseOffset + nameOffset;
                if (actualOffset + 2 > _fileBytes.Length)
                    return $"Name_{nameOffset:X}";

                ushort length = BitConverter.ToUInt16(_fileBytes, (int)actualOffset);
                if (length > 256 || actualOffset + 2 + (length * 2) > _fileBytes.Length)
                    return $"Name_{nameOffset:X}";

                var nameBytes = new byte[length * 2];
                Array.Copy(_fileBytes, actualOffset + 2, nameBytes, 0, length * 2);
                return Encoding.Unicode.GetString(nameBytes);
            }
            catch
            {
                return $"Name_{nameOffset:X}";
            }
        }

        private string GetResourceTypeName(uint id, int level)
        {
            if (level == 0)
            {
                // First level: resource type
                return id switch
                {
                    1 => "RT_CURSOR",
                    2 => "RT_BITMAP",
                    3 => "RT_ICON",
                    4 => "RT_MENU",
                    5 => "RT_DIALOG",
                    6 => "RT_STRING",
                    7 => "RT_FONTDIR",
                    8 => "RT_FONT",
                    9 => "RT_ACCELERATOR",
                    10 => "RT_RCDATA",
                    11 => "RT_MESSAGETABLE",
                    12 => "RT_GROUP_CURSOR",
                    14 => "RT_GROUP_ICON",
                    16 => "RT_VERSION",
                    17 => "RT_DLGINCLUDE",
                    19 => "RT_PLUGPLAY",
                    20 => "RT_VXD",
                    21 => "RT_ANICURSOR",
                    22 => "RT_ANIICON",
                    23 => "RT_HTML",
                    24 => "RT_MANIFEST",
                    _ => $"Type_{id}"
                };
            }

            return id.ToString();
        }

        private ResourceType GetResourceType(string path)
        {
            if (path.StartsWith("RT_ICON") || path.StartsWith("RT_GROUP_ICON"))
                return ResourceType.Icon;
            if (path.StartsWith("RT_BITMAP"))
                return ResourceType.Bitmap;
            if (path.StartsWith("RT_DIALOG"))
                return ResourceType.Dialog;
            if (path.StartsWith("RT_STRING"))
                return ResourceType.String;
            if (path.StartsWith("RT_RCDATA"))
                return ResourceType.RCData;
            if (path.StartsWith("RT_VERSION"))
                return ResourceType.Version;
            if (path.StartsWith("RT_MANIFEST"))
                return ResourceType.Manifest;

            return ResourceType.Other;
        }

        private uint GetResourceDirectoryRVA()
        {
            if (_peParser.Header == null)
                return 0;

            int dataDirectoryOffset = _peParser.Header.OptionalHeaderOffset + (_peParser.Is64Bit ? 112 : 96);

            // Resource Directory is the 3rd entry (index 2)
            int resourceDirOffset = dataDirectoryOffset + (2 * 8);

            if (resourceDirOffset + 4 > _fileBytes.Length)
                return 0;

            return BitConverter.ToUInt32(_fileBytes, resourceDirOffset);
        }

        public ResourceAnalysisResult AnalyzeResources(List<ResourceEntry> resources)
        {
            var result = new ResourceAnalysisResult
            {
                TotalResources = resources.Count,
                TotalSize = resources.Sum(r => (long)r.Size)
            };

            foreach (var resource in resources)
            {
                // Read resource data
                if (resource.Offset + resource.Size <= _fileBytes.Length)
                {
                    var data = new byte[Math.Min(resource.Size, 1024 * 1024)]; // Max 1MB
                    Array.Copy(_fileBytes, resource.Offset, data, 0, data.Length);

                    // Calculate entropy
                    resource.Entropy = new EntropyCalculator().Calculate(data);

                    // Check for suspicious characteristics
                    if (resource.Entropy > 7.0)
                    {
                        result.SuspiciousResources.Add($"{resource.Path} - High entropy ({resource.Entropy:F2})");
                    }

                    if (resource.Size > 1024 * 1024) // > 1MB
                    {
                        result.SuspiciousResources.Add($"{resource.Path} - Large size ({resource.Size:N0} bytes)");
                    }

                    // Check for embedded PE files
                    if (data.Length >= 2 && data[0] == 0x4D && data[1] == 0x5A)
                    {
                        result.SuspiciousResources.Add($"{resource.Path} - Contains embedded PE file");
                    }
                }

                // Categorize by type
                result.ResourcesByType.TryGetValue(resource.Type, out int count);
                result.ResourcesByType[resource.Type] = count + 1;
            }

            return result;
        }

        public string GenerateReport(List<ResourceEntry> resources, ResourceAnalysisResult analysis)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== RESOURCE ANALYSIS REPORT ===\n");
            sb.AppendLine($"Total Resources: {analysis.TotalResources}");
            sb.AppendLine($"Total Size: {analysis.TotalSize:N0} bytes\n");

            if (analysis.ResourcesByType.Count > 0)
            {
                sb.AppendLine("Resources by Type:");
                foreach (var kvp in analysis.ResourcesByType.OrderByDescending(x => x.Value))
                {
                    sb.AppendLine($"  {kvp.Key}: {kvp.Value}");
                }
                sb.AppendLine();
            }

            if (analysis.SuspiciousResources.Count > 0)
            {
                sb.AppendLine($"⚠ SUSPICIOUS RESOURCES ({analysis.SuspiciousResources.Count}):");
                foreach (var suspicious in analysis.SuspiciousResources)
                {
                    sb.AppendLine($"  - {suspicious}");
                }
                sb.AppendLine();
            }

            sb.AppendLine($"Resource Details (showing up to 50):");
            foreach (var resource in resources.Take(50))
            {
                sb.AppendLine($"\n  Path: {resource.Path}");
                sb.AppendLine($"  Type: {resource.Type}");
                sb.AppendLine($"  RVA: 0x{resource.RVA:X8}");
                sb.AppendLine($"  Offset: 0x{resource.Offset:X8}");
                sb.AppendLine($"  Size: {resource.Size:N0} bytes");
                sb.AppendLine($"  Entropy: {resource.Entropy:F4}");
            }

            if (resources.Count > 50)
                sb.AppendLine($"\n  ... and {resources.Count - 50} more resources");

            return sb.ToString();
        }
    }

    public class ResourceEntry
    {
        public string Path { get; set; } = string.Empty;
        public ResourceType Type { get; set; }
        public uint RVA { get; set; }
        public uint Size { get; set; }
        public uint Offset { get; set; }
        public double Entropy { get; set; }
    }

    public class ResourceAnalysisResult
    {
        public int TotalResources { get; set; }
        public long TotalSize { get; set; }
        public Dictionary<ResourceType, int> ResourcesByType { get; set; } = new();
        public List<string> SuspiciousResources { get; set; } = new();
    }

    public enum ResourceType
    {
        Icon,
        Bitmap,
        Dialog,
        String,
        RCData,
        Version,
        Manifest,
        Other
    }
}