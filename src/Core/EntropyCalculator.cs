using System;
using System.Linq;

namespace PEye.Core
{
    public class EntropyCalculator
    {
        /// <summary>
        /// Calculate Shannon entropy of byte array
        /// Returns value between 0 (no randomness) and 8 (maximum randomness)
        /// Values > 7.0 typically indicate encryption or compression
        /// </summary>
        public double Calculate(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0.0;

            // Count frequency of each byte value (0-255)
            var frequency = new int[256];
            foreach (byte b in data)
            {
                frequency[b]++;
            }

            double entropy = 0.0;
            int length = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] == 0)
                    continue;

                double probability = (double)frequency[i] / length;
                entropy -= probability * Math.Log(probability, 2);
            }

            return entropy;
        }

        /// <summary>
        /// Calculate entropy for sliding windows across the data
        /// Useful for detecting packed/encrypted regions
        /// </summary>
        public EntropyWindow[] CalculateWindowed(byte[] data, int windowSize = 1024)
        {
            if (data == null || data.Length < windowSize)
                return Array.Empty<EntropyWindow>();

            int numWindows = (data.Length - windowSize) / (windowSize / 2) + 1;
            var windows = new EntropyWindow[numWindows];

            for (int i = 0; i < numWindows; i++)
            {
                int offset = i * (windowSize / 2);
                if (offset + windowSize > data.Length)
                    offset = data.Length - windowSize;

                byte[] window = new byte[windowSize];
                Array.Copy(data, offset, window, 0, windowSize);

                windows[i] = new EntropyWindow
                {
                    Offset = offset,
                    Size = windowSize,
                    Entropy = Calculate(window)
                };

                if (offset + windowSize >= data.Length)
                    break;
            }

            return windows.Where(w => w.Entropy > 0).ToArray();
        }

        /// <summary>
        /// Classify data based on entropy
        /// </summary>
        public EntropyClassification Classify(double entropy)
        {
            if (entropy < 1.0)
                return EntropyClassification.VeryLow;
            else if (entropy < 3.0)
                return EntropyClassification.Low;
            else if (entropy < 5.0)
                return EntropyClassification.Medium;
            else if (entropy < 7.0)
                return EntropyClassification.High;
            else
                return EntropyClassification.VeryHigh;
        }

        /// <summary>
        /// Detect suspicious entropy patterns
        /// </summary>
        public EntropySuspicionResult DetectSuspiciousEntropy(byte[] data)
        {
            double overallEntropy = Calculate(data);
            var windows = CalculateWindowed(data, Math.Min(1024, data.Length / 10));

            var result = new EntropySuspicionResult
            {
                OverallEntropy = overallEntropy,
                Classification = Classify(overallEntropy),
                IsSuspicious = false,
                Reasons = new System.Collections.Generic.List<string>()
            };

            // Check overall entropy
            if (overallEntropy > 7.5)
            {
                result.IsSuspicious = true;
                result.Reasons.Add("Very high overall entropy suggests encryption/packing");
            }

            // Check for high-entropy regions
            if (windows.Length > 0)
            {
                var highEntropyWindows = windows.Where(w => w.Entropy > 7.0).ToArray();
                if (highEntropyWindows.Length > windows.Length * 0.3)
                {
                    result.IsSuspicious = true;
                    result.Reasons.Add($"{highEntropyWindows.Length} high-entropy regions detected");
                }

                // Check for entropy variance (multiple distinct regions)
                double avgEntropy = windows.Average(w => w.Entropy);
                double variance = windows.Average(w => Math.Pow(w.Entropy - avgEntropy, 2));
                if (variance > 4.0)
                {
                    result.Reasons.Add("High entropy variance suggests mixed packed/unpacked code");
                }
            }

            return result;
        }
    }

    public class EntropyWindow
    {
        public int Offset { get; set; }
        public int Size { get; set; }
        public double Entropy { get; set; }
    }

    public enum EntropyClassification
    {
        VeryLow,    // < 1.0
        Low,        // 1.0 - 3.0
        Medium,     // 3.0 - 5.0
        High,       // 5.0 - 7.0
        VeryHigh    // > 7.0 (likely packed/encrypted)
    }

    public class EntropySuspicionResult
    {
        public double OverallEntropy { get; set; }
        public EntropyClassification Classification { get; set; }
        public bool IsSuspicious { get; set; }
        public System.Collections.Generic.List<string> Reasons { get; set; } = new();
    }
}