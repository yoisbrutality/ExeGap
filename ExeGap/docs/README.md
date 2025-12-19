# ExeGap 3.0.1 - Professional Binary Analysis Suite

> **Advanced PE Binary Analysis & Decompilation Toolkit**
>
> Enterprise-grade security analysis, resource extraction, and embedded file recovery for Windows PE executables.

ExeGap is a comprehensive professional-grade binary analysis platform designed for security researchers, malware analysts, and reverse engineers.

## Features

### 🔧 Core Decompilation & Extraction
- **PE Resource Extraction**: Extract all resources from `.rsrc` directory with metadata
- **File Carving**: Advanced signature-based carving for 20+ file types (ZIP, 7z, RAR, PE, DLL, images, audio, PDFs, etc.)
- **Embedded Binary Detection**: Identify and extract nested PE/DLL executables
- **String Analysis**: Extract ASCII and Unicode strings with URL/IP intelligence

### 🛡️ Security Analysis
- **Packing Detection**: Identify packed/encrypted binaries using entropy analysis
- **API Hook Detection**: Detect common code injection and hooking patterns
- **Import Analysis**: Categorize imported functions by behavior (process injection, hooking, memory ops, etc.)
- **Malware Behavior Signatures**: Classify potential malware behavior (worm, ransomware, spyware, rootkit, trojan)
- **Debug Information Extraction**: Retrieve debug directory and symbol information

### .NET Assembly Analysis
- **CLR Metadata Parsing**: Extract .NET metadata and assembly information
- **IL Code Analysis**: Disassemble IL (Intermediate Language) instructions
- **Manifest Extraction**: Parse application manifests
- **.NET Version Detection**: Identify runtime version and framework

### x86/x64 Assembly Analysis
- **Disassembly**: Full x86/x64 disassembly using Capstone engine
- **Instruction Analysis**: Detailed instruction-level analysis
- **Section Analysis**: Per-section code analysis

### 📊 Web Dashboard
- **Beautiful Web UI**: Real-time analysis visualization
- **Interactive Reports**: Explore analysis results with rich interface
- **File Management**: Browse and download extracted files
- **Responsive Design**: Works on desktop and mobile

### 🚀 Batch Processing
- **Parallel Processing**: Analyze multiple files simultaneously
- **Batch Reporting**: Generate CSV/JSON/HTML reports
- **Directory Scanning**: Process entire directories with file pattern matching

## Installation

```bash
cd Nova\ pasta

pip install -r requirements.txt
```

**Requirements**: Python 3.8+

## Quick Start

### Single File Analysis

```bash
python cli.py analyze sample.exe

python cli.py analyze sample.exe --hooks

python cli.py analyze sample.exe --dotnet

python cli.py analyze sample.exe -o ./results
```

### Batch Processing

```bash
python cli.py batch /path/to/samples *.exe

python cli.py batch ./samples *.exe -o batch_results --workers 8
```

### Web Dashboard

```bash
python cli.py dashboard

python cli.py dashboard --port 8080 --debug
```

### Generate Reports

```bash
python cli.py report decompiled_output/analysis_report.json report.html --format html

python cli.py report decompiled_output/analysis_report.json report.json --format json
```

## Module Reference

### decompiler_suite.py
Main analysis engine with security analysis, resource extraction, and file carving.

```python
from decompiler_suite import DecompilerSuite

suite = DecompilerSuite('sample.exe', 'output_dir')
report = suite.run_full_analysis({
    'security': True,
    'resources': True,
    'carve': True,
    'strings': True,
    'dotnet': True,
    'debug': True
})
```

### api_hook_detector.py
Detects API hooks, imports, and malware behavior patterns.

```python
from api_hook_detector import ImportAnalyzerSuite

analyzer = ImportAnalyzerSuite('sample.exe')
report = analyzer.run_analysis()
```

### dotnet_analyzer.py
Analyzes .NET assemblies and CLR metadata.

```python
from dotnet_analyzer import DotNetDecompiler

decompiler = DotNetDecompiler('assembly.exe')
result = decompiler.decompile()
```

### dashboard.py
Flask-based web dashboard for visualization.

```python
from dashboard import start_dashboard

start_dashboard(port=5000, debug=False)
```

## Output Structure

```
decompiled_output/
├── resources/              # Extracted PE resources
├── carved/                 # Carved embedded files
├── embedded_pe/            # Extracted PE executables
├── ascii_strings.txt       # Extracted ASCII strings
├── unicode_strings.txt     # Extracted Unicode strings
└── analysis_report.json    # Complete analysis report
```

## Advanced Usage

### Custom Analysis Script

```python
from decompiler_suite import DecompilerSuite, SecurityAnalyzer, ResourceExtractor
import pefile

pe = pefile.PE('binary.exe')

security = SecurityAnalyzer.detect_packing(pe)
imports = SecurityAnalyzer.extract_imports(pe)
exports = SecurityAnalyzer.extract_exports(pe)

print(f"Packed: {security['packed']}")
print(f"Suspicious sections: {security['suspicious_sections']}")
print(f"Imported DLLs: {len(imports)}")
```

### File Carving

```python
from decompiler_suite import CarvingEngine

with open('binary.exe', 'rb') as f:
    data = f.read()

carver = CarvingEngine(data)
carvings = carver.carve_files('output_dir', min_size=64)
print(f"Carved {len(carvings)} files")
```

## Security & Ethics

⚠️ **Important**: This tool is designed for authorized security research and malware analysis only.

- **Legal**: Only analyze binaries you own or have explicit permission to analyze
- **Responsible**: Report vulnerabilities through proper channels
- **Ethical**: Respect intellectual property and privacy

## Limitations

- Heuristic-based carving may produce false positives
- .NET decompilation provides metadata extraction, not full source code
- Assembly analysis requires external tools for full disassembly
- Some anti-analysis techniques may evade detection

## Supported File Types for Carving

- ZIP archives
- 7z archives
- RAR archives
- GZIP archives
- PE executables and DLLs
- BMP, PNG, JPEG, GIF, TIFF images
- WAV, MP3 audio
- PDF documents
- ELF binaries
- Java classes

## Troubleshooting

**ImportError: No module named 'pefile'**
```bash
pip install pefile capstone flask
```

**PE parsing errors**
- Ensure the file is a valid PE binary
- Try with fast_load option

**Dashboard not starting**
- Check if port 5000 is available
- Use `--port` to specify alternative port

## Performance Tips

- For large directories, use batch processing with multiple workers
- Disable unused analysis modules to speed up processing
- Use `--no-carve` flag if file carving is not needed
- Run on SSD for better I/O performance

## Contributing

Contributions welcome! Areas for enhancement:
- Additional file signature support
- Better .NET decompilation
- Enhanced malware behavior detection
- More analysis modules

## License

This project is provided for authorized security research purposes only.

## Disclaimer

This tool is provided as-is. The authors are not responsible for misuse or damage caused by this tool. Use responsibly and legally.