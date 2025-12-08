using System;
using System.Text;

namespace PEye.Utils
{
    public static class Helpers
    {
        public static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        PEye v1.0                                          ║
║        Windows PE Analysis Tool                           ║
║        Developed by: Ehabal7ab                            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
");
            Console.ResetColor();
        }

        public static void PrintSection(string title)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n{'═', 60}");
            Console.WriteLine($"  {title}");
            Console.WriteLine($"{'═', 60}\n");
            Console.ResetColor();
        }

        public static void PrintSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[✓] {message}");
            Console.ResetColor();
        }

        public static void PrintError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[✗] {message}");
            Console.ResetColor();
        }

        public static void PrintWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"[!] {message}");
            Console.ResetColor();
        }

        public static void PrintInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[*] {message}");
            Console.ResetColor();
        }

        public static string FormatTimestamp(DateTime dateTime)
        {
            return dateTime.ToString("yyyy-MM-dd HH:mm:ss UTC");
        }

        public static string GenerateReportHeader(string fileName, DateTime analysisTime)
        {
            var sb = new StringBuilder();
            sb.AppendLine("╔════════════════════════════════════════════════════════════════════╗");
            sb.AppendLine("║          PEye STATIC ANALYSIS REPORT                                ║");
            sb.AppendLine("╚════════════════════════════════════════════════════════════════════╝");
            sb.AppendLine();
            sb.AppendLine($"File:            {fileName}");
            sb.AppendLine($"Analysis Time:   {FormatTimestamp(analysisTime)}");
            sb.AppendLine($"Analyzer:        PEye v1.0");
            sb.AppendLine();
            sb.AppendLine("════════════════════════════════════════════════════════════════════");
            sb.AppendLine();
            return sb.ToString();
        }

        public static string GenerateReportFooter()
        {
            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine("════════════════════════════════════════════════════════════════════");
            sb.AppendLine("                     END OF REPORT");
            sb.AppendLine("════════════════════════════════════════════════════════════════════");
            return sb.ToString();
        }

        public static void ProgressBar(int current, int total, string message = "")
        {
            int barLength = 40;
            int progress = (int)((double)current / total * barLength);

            Console.Write("\r[");
            Console.Write(new string('█', progress));
            Console.Write(new string('░', barLength - progress));
            Console.Write($"] {current}/{total}");
            
            if (!string.IsNullOrEmpty(message))
                Console.Write($" - {message}");

            if (current == total)
                Console.WriteLine();
        }

        public static string ByteArrayToHexString(byte[] bytes, int maxLength = 16)
        {
            var sb = new StringBuilder();
            int length = Math.Min(bytes.Length, maxLength);

            for (int i = 0; i < length; i++)
            {
                sb.Append($"{bytes[i]:X2} ");
            }

            if (bytes.Length > maxLength)
                sb.Append("...");

            return sb.ToString().TrimEnd();
        }
    }
}