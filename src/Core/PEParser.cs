using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PEye.Core
{
    public class PEParser
    {
        private byte[] _fileBytes;
        private string _filePath;

        public PEHeader? Header { get; private set; }
        public bool IsPE { get; private set; }
        public bool Is64Bit { get; private set; }

        public PEParser(string filePath)
        {
            _filePath = filePath;
            _fileBytes = File.ReadAllBytes(filePath);
            Parse();
        }

        private void Parse()
        {
            if (_fileBytes.Length < 64)
            {
                IsPE = false;
                return;
            }

            // Check DOS signature "MZ"
            if (_fileBytes[0] != 0x4D || _fileBytes[1] != 0x5A)
            {
                IsPE = false;
                return;
            }

            // Get PE offset from DOS header at offset 0x3C
            int peOffset = BitConverter.ToInt32(_fileBytes, 0x3C);

            if (peOffset + 4 >= _fileBytes.Length)
            {
                IsPE = false;
                return;
            }

            // Check PE signature "PE\0\0"
            if (_fileBytes[peOffset] != 0x50 || _fileBytes[peOffset + 1] != 0x45 ||
                _fileBytes[peOffset + 2] != 0x00 || _fileBytes[peOffset + 3] != 0x00)
            {
                IsPE = false;
                return;
            }

            IsPE = true;

            // Parse COFF header
            ushort machine = BitConverter.ToUInt16(_fileBytes, peOffset + 4);
            ushort numberOfSections = BitConverter.ToUInt16(_fileBytes, peOffset + 6);
            uint timeDateStamp = BitConverter.ToUInt32(_fileBytes, peOffset + 8);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(_fileBytes, peOffset + 20);
            ushort characteristics = BitConverter.ToUInt16(_fileBytes, peOffset + 22);

            Is64Bit = (machine == 0x8664); // IMAGE_FILE_MACHINE_AMD64

            int optionalHeaderOffset = peOffset + 24;
            ushort magic = BitConverter.ToUInt16(_fileBytes, optionalHeaderOffset);

            // Verify magic number
            if (magic == 0x10B) // PE32
            {
                Is64Bit = false;
            }
            else if (magic == 0x20B) // PE32+
            {
                Is64Bit = true;
            }

            Header = new PEHeader
            {
                Machine = machine,
                NumberOfSections = numberOfSections,
                TimeDateStamp = timeDateStamp,
                SizeOfOptionalHeader = sizeOfOptionalHeader,
                Characteristics = characteristics,
                Magic = magic,
                PEOffset = peOffset,
                OptionalHeaderOffset = optionalHeaderOffset
            };

            ParseOptionalHeader(optionalHeaderOffset);
            ParseSections();
        }

        private void ParseOptionalHeader(int offset)
        {
            if (Header == null) return;

            int currentOffset = offset + 2; // Skip magic

            if (Is64Bit)
            {
                // PE32+ format
                Header.MajorLinkerVersion = _fileBytes[currentOffset++];
                Header.MinorLinkerVersion = _fileBytes[currentOffset++];
                Header.SizeOfCode = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.SizeOfInitializedData = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.SizeOfUninitializedData = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.AddressOfEntryPoint = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.BaseOfCode = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.ImageBase = BitConverter.ToUInt64(_fileBytes, currentOffset);
                currentOffset += 8;
            }
            else
            {
                // PE32 format
                Header.MajorLinkerVersion = _fileBytes[currentOffset++];
                Header.MinorLinkerVersion = _fileBytes[currentOffset++];
                Header.SizeOfCode = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.SizeOfInitializedData = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.SizeOfUninitializedData = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.AddressOfEntryPoint = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.BaseOfCode = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                uint baseOfData = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
                Header.ImageBase = BitConverter.ToUInt32(_fileBytes, currentOffset);
                currentOffset += 4;
            }

            Header.SectionAlignment = BitConverter.ToUInt32(_fileBytes, currentOffset);
            currentOffset += 4;
            Header.FileAlignment = BitConverter.ToUInt32(_fileBytes, currentOffset);
            currentOffset += 4;

            // Skip version fields
            currentOffset += 16;

            Header.SizeOfImage = BitConverter.ToUInt32(_fileBytes, currentOffset);
            currentOffset += 4;
            Header.SizeOfHeaders = BitConverter.ToUInt32(_fileBytes, currentOffset);
            currentOffset += 4;
            Header.CheckSum = BitConverter.ToUInt32(_fileBytes, currentOffset);
            currentOffset += 4;
            Header.Subsystem = BitConverter.ToUInt16(_fileBytes, currentOffset);
            currentOffset += 2;
            Header.DllCharacteristics = BitConverter.ToUInt16(_fileBytes, currentOffset);
        }

        private void ParseSections()
        {
            if (Header == null) return;

            int sectionTableOffset = Header.OptionalHeaderOffset + Header.SizeOfOptionalHeader;
            Header.Sections = new SectionHeader[Header.NumberOfSections];

            for (int i = 0; i < Header.NumberOfSections; i++)
            {
                int offset = sectionTableOffset + (i * 40);

                var section = new SectionHeader
                {
                    Name = Encoding.ASCII.GetString(_fileBytes, offset, 8).TrimEnd('\0'),
                    VirtualSize = BitConverter.ToUInt32(_fileBytes, offset + 8),
                    VirtualAddress = BitConverter.ToUInt32(_fileBytes, offset + 12),
                    SizeOfRawData = BitConverter.ToUInt32(_fileBytes, offset + 16),
                    PointerToRawData = BitConverter.ToUInt32(_fileBytes, offset + 20),
                    Characteristics = BitConverter.ToUInt32(_fileBytes, offset + 36)
                };

                Header.Sections[i] = section;
            }
        }

        public byte[] GetSectionData(SectionHeader section)
        {
            byte[] data = new byte[section.SizeOfRawData];
            Array.Copy(_fileBytes, section.PointerToRawData, data, 0, section.SizeOfRawData);
            return data;
        }

        public byte[] GetFileBytes() => _fileBytes;

        public uint RvaToFileOffset(uint rva)
        {
            if (Header?.Sections == null) return rva;

            foreach (var section in Header.Sections)
            {
                if (rva >= section.VirtualAddress && 
                    rva < section.VirtualAddress + section.VirtualSize)
                {
                    return rva - section.VirtualAddress + section.PointerToRawData;
                }
            }

            return rva;
        }
    }

    public class PEHeader
    {
        public ushort Machine { get; set; }
        public ushort NumberOfSections { get; set; }
        public uint TimeDateStamp { get; set; }
        public ushort SizeOfOptionalHeader { get; set; }
        public ushort Characteristics { get; set; }
        public ushort Magic { get; set; }
        public int PEOffset { get; set; }
        public int OptionalHeaderOffset { get; set; }
        public byte MajorLinkerVersion { get; set; }
        public byte MinorLinkerVersion { get; set; }
        public uint SizeOfCode { get; set; }
        public uint SizeOfInitializedData { get; set; }
        public uint SizeOfUninitializedData { get; set; }
        public uint AddressOfEntryPoint { get; set; }
        public uint BaseOfCode { get; set; }
        public ulong ImageBase { get; set; }
        public uint SectionAlignment { get; set; }
        public uint FileAlignment { get; set; }
        public uint SizeOfImage { get; set; }
        public uint SizeOfHeaders { get; set; }
        public uint CheckSum { get; set; }
        public ushort Subsystem { get; set; }
        public ushort DllCharacteristics { get; set; }
        public SectionHeader[] Sections { get; set; } = Array.Empty<SectionHeader>();

        public DateTime GetCompileTime()
        {
            return DateTimeOffset.FromUnixTimeSeconds(TimeDateStamp).DateTime;
        }
    }

    public class SectionHeader
    {
        public string Name { get; set; } = string.Empty;
        public uint VirtualSize { get; set; }
        public uint VirtualAddress { get; set; }
        public uint SizeOfRawData { get; set; }
        public uint PointerToRawData { get; set; }
        public uint Characteristics { get; set; }

        public bool IsExecutable => (Characteristics & 0x20000000) != 0;
        public bool IsWritable => (Characteristics & 0x80000000) != 0;
        public bool IsReadable => (Characteristics & 0x40000000) != 0;
    }
}