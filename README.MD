# PEye 

Short overview
- PEye is an educational tool written in C# that helps you inspect Portable Executable (PE) files using static analysis techniques. It consolidates several common inspection steps into a single, easy-to-use utility so learners can understand and practice PE analysis workflows.

What the tool does
- Reads PE headers (DOS/NT/Optional headers) and presents basic header information.
- Lists sections with attributes, sizes, and computed entropy to help spot packed or suspicious sections.
- Extracts Import and Export tables to show libraries and API calls used.
- Searches and displays important strings embedded in the binary.
- Inspects resources, certificates (if present), and other common PE structures.
- Highlights simple heuristics and indicators that may be of interest to a human analyst (e.g., unusual section flags, network-related API imports, high entropy values).
- Produces a concise report that aggregates findings for manual review.

How it works (brief)
1. Opens the target file and parses DOS and PE headers.
2. Reads and analyzes section headers and content (size, flags, entropy).
3. Parses import/export tables and checks for APIs commonly used by malware.
4. Collects strings and resource information.
5. Outputs a summarized report intended to guide a human analyst to suspicious areas.

Key features
- Command-line interface for quick analysis.
- Single consolidated report containing headers, sections, imports/exports, resources, and strings.
- Lightweight heuristics to surface potentially interesting indicators.
- Works offline by default; does not rely on external threat feeds unless you add them.

Important notice (read carefully)
- This tool is built for educational purposes only. Its purpose is to simplify and demonstrate the static-analysis steps used when inspecting PE files.
- The output is not a definitive determination that a file is malicious or benign. Do NOT treat the tool’s results as a final verdict. False positives and false negatives are possible.
- Use multiple analysis methods (including dynamic analysis in an isolated environment, specialized scanners, and threat intelligence sources) before drawing conclusions.
- Do not execute untrusted or suspicious binaries on production systems. Always use isolated VMs or sandbox environments.

Requirements
- .NET 6.0 or later (or the .NET version targeted by the project).
- A platform that supports .NET applications (Windows / Linux / macOS as appropriate).

Build and run (example)
1. Clone the repository:
   git clone https://github.com/CyberX-sec/PEye.git
   cd PEye
2. Build the project:
   dotnet build
3. Run an analysis:
   dotnet run --project PEye -- path/to/sample.exe

Usage and safety
- The tool is intended to assist learning and manual analysis workflows, not to automate final decisions.
- Do not use the tool to perform or support malicious activity. The author is not responsible for misuse.
