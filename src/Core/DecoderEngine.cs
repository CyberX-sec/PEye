using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PEye.Core
{
    public class DecoderEngine
    {
        private readonly int _minStringLength;
        private readonly int _maxKeyLength;

        public DecoderEngine(int minStringLength = 4, int maxKeyLength = 256)
        {
            _minStringLength = minStringLength;
            _maxKeyLength = maxKeyLength;
        }

        /// <summary>
        /// Attempts to decode XOR-encoded strings in the data
        /// </summary>
        public List<DecodedString> DecodeXorStrings(byte[] data)
        {
            var results = new List<DecodedString>();

            // Try single-byte XOR keys (0x01 - 0xFF)
            for (int key = 1; key < 256; key++)
            {
                var decoded = XorDecode(data, new byte[] { (byte)key });
                var strings = ExtractPrintableStrings(decoded);

                foreach (var str in strings)
                {
                    if (str.Length >= _minStringLength && IsMeaningfulString(str))
                    {
                        results.Add(new DecodedString
                        {
                            Value = str,
                            Method = DecodingMethod.XorSingleByte,
                            Key = new byte[] { (byte)key },
                            KeyHex = $"0x{key:X2}",
                            Confidence = CalculateConfidence(str)
                        });
                    }
                }
            }

            // Try multi-byte XOR keys (common patterns)
            var commonKeys = GenerateCommonXorKeys();
            foreach (var key in commonKeys)
            {
                var decoded = XorDecode(data, key);
                var strings = ExtractPrintableStrings(decoded);

                foreach (var str in strings)
                {
                    if (str.Length >= _minStringLength && IsMeaningfulString(str))
                    {
                        results.Add(new DecodedString
                        {
                            Value = str,
                            Method = DecodingMethod.XorMultiByte,
                            Key = key,
                            KeyHex = BitConverter.ToString(key).Replace("-", " "),
                            Confidence = CalculateConfidence(str)
                        });
                    }
                }
            }

            // Remove duplicates and sort by confidence
            return results
                .GroupBy(d => d.Value)
                .Select(g => g.OrderByDescending(d => d.Confidence).First())
                .OrderByDescending(d => d.Confidence)
                .ToList();
        }

        /// <summary>
        /// Attempts to decode ROT-encoded strings
        /// </summary>
        public List<DecodedString> DecodeRotStrings(byte[] data)
        {
            var results = new List<DecodedString>();
            var asciiData = Encoding.ASCII.GetString(data.Where(b => b >= 32 && b <= 126).ToArray());

            // Try ROT-1 through ROT-25
            for (int rotation = 1; rotation < 26; rotation++)
            {
                var decoded = RotDecode(asciiData, rotation);
                
                if (decoded.Length >= _minStringLength && IsMeaningfulString(decoded))
                {
                    results.Add(new DecodedString
                    {
                        Value = decoded,
                        Method = DecodingMethod.Rot,
                        Key = new byte[] { (byte)rotation },
                        KeyHex = $"ROT{rotation}",
                        Confidence = CalculateConfidence(decoded)
                    });
                }
            }

            return results.OrderByDescending(d => d.Confidence).ToList();
        }

        /// <summary>
        /// Attempts to decode Base64 encoded strings
        /// </summary>
        public List<DecodedString> DecodeBase64Strings(byte[] data)
        {
            var results = new List<DecodedString>();
            var strings = new StringExtractor(8).Extract(data);

            foreach (var str in strings.AsciiStrings.Concat(strings.UnicodeStrings))
            {
                if (IsBase64Candidate(str.Value))
                {
                    try
                    {
                        var decoded = Convert.FromBase64String(str.Value);
                        var decodedStr = Encoding.UTF8.GetString(decoded);

                        if (IsPrintableString(decodedStr))
                        {
                            results.Add(new DecodedString
                            {
                                Value = decodedStr,
                                Method = DecodingMethod.Base64,
                                OriginalOffset = str.Offset,
                                OriginalValue = str.Value,
                                Confidence = CalculateConfidence(decodedStr)
                            });
                        }
                    }
                    catch
                    {
                        // Not valid Base64, continue
                    }
                }
            }

            return results.OrderByDescending(d => d.Confidence).ToList();
        }

        /// <summary>
        /// Attempts Caesar cipher decoding
        /// </summary>
        public List<DecodedString> DecodeCaesarCipher(string input)
        {
            var results = new List<DecodedString>();

            for (int shift = 1; shift < 26; shift++)
            {
                var decoded = CaesarDecode(input, shift);
                
                if (IsMeaningfulString(decoded))
                {
                    results.Add(new DecodedString
                    {
                        Value = decoded,
                        Method = DecodingMethod.Caesar,
                        Key = new byte[] { (byte)shift },
                        KeyHex = $"Shift {shift}",
                        Confidence = CalculateConfidence(decoded)
                    });
                }
            }

            return results.OrderByDescending(d => d.Confidence).ToList();
        }

        /// <summary>
        /// Comprehensive decode attempt using all methods
        /// </summary>
        public DecodingResult DecodeAll(byte[] data)
        {
            var result = new DecodingResult();

            Console.WriteLine("[*] Attempting XOR decoding...");
            result.XorDecoded = DecodeXorStrings(data);
            
            Console.WriteLine("[*] Attempting ROT decoding...");
            result.RotDecoded = DecodeRotStrings(data);
            
            Console.WriteLine("[*] Attempting Base64 decoding...");
            result.Base64Decoded = DecodeBase64Strings(data);

            result.TotalDecoded = result.XorDecoded.Count + 
                                 result.RotDecoded.Count + 
                                 result.Base64Decoded.Count;

            return result;
        }

        #region Helper Methods

        private byte[] XorDecode(byte[] data, byte[] key)
        {
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return result;
        }

        private string RotDecode(string input, int rotation)
        {
            var result = new StringBuilder();
            foreach (char c in input)
            {
                if (char.IsLetter(c))
                {
                    char offset = char.IsUpper(c) ? 'A' : 'a';
                    result.Append((char)((c - offset + rotation) % 26 + offset));
                }
                else
                {
                    result.Append(c);
                }
            }
            return result.ToString();
        }

        private string CaesarDecode(string input, int shift)
        {
            var result = new StringBuilder();
            foreach (char c in input)
            {
                if (char.IsLetter(c))
                {
                    char offset = char.IsUpper(c) ? 'A' : 'a';
                    char decoded = (char)(((c - offset - shift + 26) % 26) + offset);
                    result.Append(decoded);
                }
                else
                {
                    result.Append(c);
                }
            }
            return result.ToString();
        }

        private List<string> ExtractPrintableStrings(byte[] data)
        {
            var strings = new List<string>();
            var current = new StringBuilder();

            foreach (byte b in data)
            {
                if (b >= 32 && b <= 126)
                {
                    current.Append((char)b);
                }
                else
                {
                    if (current.Length >= _minStringLength)
                    {
                        strings.Add(current.ToString());
                    }
                    current.Clear();
                }
            }

            if (current.Length >= _minStringLength)
            {
                strings.Add(current.ToString());
            }

            return strings;
        }

        private bool IsPrintableString(string str)
        {
            return str.All(c => (c >= 32 && c <= 126) || char.IsWhiteSpace(c));
        }

        private bool IsBase64Candidate(string str)
        {
            // Must be reasonable length
            if (str.Length < 8 || str.Length % 4 != 0)
                return false;

            // Check for Base64 character set
            var base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            return str.All(c => base64Chars.Contains(c));
        }

        private bool IsMeaningfulString(string str)
        {
            if (string.IsNullOrWhiteSpace(str))
                return false;

            // Check for reasonable character distribution
            int letters = str.Count(char.IsLetter);
            int digits = str.Count(char.IsDigit);
            int spaces = str.Count(char.IsWhiteSpace);
            int special = str.Length - letters - digits - spaces;

            // Should be mostly letters
            double letterRatio = (double)letters / str.Length;
            if (letterRatio < 0.5)
                return false;

            // Check for common English words (simple heuristic)
            var commonWords = new[] { "the", "and", "for", "are", "but", "not", "you", "all", "can", "her", "was", "one", "our", "out", "http", "www", "exe", "dll", "sys" };
            string lower = str.ToLower();
            if (commonWords.Any(word => lower.Contains(word)))
                return true;

            // Check entropy (meaningful text has moderate entropy)
            var entropy = new EntropyCalculator().Calculate(Encoding.ASCII.GetBytes(str));
            if (entropy > 2.0 && entropy < 5.0)
                return true;

            return false;
        }

        private double CalculateConfidence(string str)
        {
            double confidence = 0.0;

            // Length factor
            if (str.Length >= 10)
                confidence += 0.2;
            if (str.Length >= 20)
                confidence += 0.1;

            // Letter ratio
            int letters = str.Count(char.IsLetter);
            double letterRatio = (double)letters / str.Length;
            confidence += letterRatio * 0.3;

            // Common words
            var commonWords = new[] { "http", "https", "www", "windows", "microsoft", "system", "program", "files", "temp", "appdata" };
            string lower = str.ToLower();
            int wordMatches = commonWords.Count(word => lower.Contains(word));
            confidence += Math.Min(wordMatches * 0.1, 0.3);

            // Entropy (moderate is good)
            var entropy = new EntropyCalculator().Calculate(Encoding.ASCII.GetBytes(str));
            if (entropy >= 3.0 && entropy <= 5.0)
                confidence += 0.2;

            return Math.Min(confidence, 1.0);
        }

        private List<byte[]> GenerateCommonXorKeys()
        {
            var keys = new List<byte[]>();

            // Common multi-byte patterns
            keys.Add(new byte[] { 0xAA, 0xBB });
            keys.Add(new byte[] { 0xDE, 0xAD });
            keys.Add(new byte[] { 0xBE, 0xEF });
            keys.Add(new byte[] { 0xCA, 0xFE });
            keys.Add(new byte[] { 0xBA, 0xBE });
            keys.Add(new byte[] { 0x13, 0x37 });

            // "MALW" pattern
            keys.Add(Encoding.ASCII.GetBytes("MALW"));
            keys.Add(Encoding.ASCII.GetBytes("PACK"));
            keys.Add(Encoding.ASCII.GetBytes("KEY"));

            return keys;
        }

        #endregion

        public string GenerateReport(DecodingResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== DECODING ENGINE REPORT ===\n");
            sb.AppendLine($"Total Decoded Strings: {result.TotalDecoded}\n");

            if (result.XorDecoded.Count > 0)
            {
                sb.AppendLine($"XOR Decoded ({result.XorDecoded.Count}):");
                foreach (var decoded in result.XorDecoded.Take(20))
                {
                    sb.AppendLine($"  Key: {decoded.KeyHex} | Confidence: {decoded.Confidence:F2}");
                    sb.AppendLine($"  Value: {Truncate(decoded.Value, 80)}\n");
                }
                if (result.XorDecoded.Count > 20)
                    sb.AppendLine($"  ... and {result.XorDecoded.Count - 20} more\n");
            }

            if (result.Base64Decoded.Count > 0)
            {
                sb.AppendLine($"Base64 Decoded ({result.Base64Decoded.Count}):");
                foreach (var decoded in result.Base64Decoded.Take(10))
                {
                    sb.AppendLine($"  Offset: 0x{decoded.OriginalOffset:X8} | Confidence: {decoded.Confidence:F2}");
                    sb.AppendLine($"  Original: {Truncate(decoded.OriginalValue ?? "", 60)}");
                    sb.AppendLine($"  Decoded: {Truncate(decoded.Value, 60)}\n");
                }
                if (result.Base64Decoded.Count > 10)
                    sb.AppendLine($"  ... and {result.Base64Decoded.Count - 10} more\n");
            }

            if (result.RotDecoded.Count > 0)
            {
                sb.AppendLine($"ROT Decoded ({result.RotDecoded.Count}):");
                foreach (var decoded in result.RotDecoded.Take(10))
                {
                    sb.AppendLine($"  {decoded.KeyHex} | Confidence: {decoded.Confidence:F2}");
                    sb.AppendLine($"  Value: {Truncate(decoded.Value, 80)}\n");
                }
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

    public class DecodedString
    {
        public string Value { get; set; } = string.Empty;
        public DecodingMethod Method { get; set; }
        public byte[]? Key { get; set; }
        public string KeyHex { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public int OriginalOffset { get; set; }
        public string? OriginalValue { get; set; }
    }

    public class DecodingResult
    {
        public List<DecodedString> XorDecoded { get; set; } = new();
        public List<DecodedString> RotDecoded { get; set; } = new();
        public List<DecodedString> Base64Decoded { get; set; } = new();
        public int TotalDecoded { get; set; }
    }

    public enum DecodingMethod
    {
        XorSingleByte,
        XorMultiByte,
        Rot,
        Caesar,
        Base64
    }
}