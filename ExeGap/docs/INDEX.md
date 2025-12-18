# Documentation

Navigate the guides you need.

## Getting Started

- **[Quick Start](QUICKSTART.md)** - 5 minute setup
- **[Usage Guide](USAGE.md)** - Examples and use cases
- **[Command Reference](QUICK_REFERENCE.md)** - All commands

## Building

- **[Build Guide](BUILD_GUIDE.md)** - Compile to .exe

## Understanding the Project

- **[Folder Structure](FOLDER_STRUCTURE.md)** - How code is organized
- **[README](../README.md)** - Overview

## What You Can Do

```bash
# Analyze files
python main.py analyze target.exe

# Detect API hooks
python main.py analyze target.exe --hooks

# Extract secrets
python main.py analyze target.exe --config

# Carve embedded files
python main.py analyze target.exe --carve

# .NET analysis
python main.py analyze target.exe --dotnet

# GUI
python main.py gui

# Web dashboard
python main.py dashboard --port 5000

# Batch processing
python main.py batch ./samples *.exe --workers 4
```

That covers 95% of what you'll need. Start with [Quick Start](QUICKSTART.md) or [Usage Guide](USAGE.md).
- `parse_metadata_header()` - Parse metadata root
- `extract_assembly_info()` - Get assembly metadata
- `disassemble_il()` - Disassemble IL code

### 4. **config_extractor.py** - Secrets & Configuration
- **ConfigExtractor**: Regex-based secret/credential finding
- **HardcodedCredentialFinder**: Weak credential detection
- **EncodingDetector**: Base64/Hex encoded string detection
- **IntelligenceExtractor**: IOC extraction (URLs, IPs, domains, hashes, emails)
- **SecretExtractorSuite**: Orchestrates extraction

**Key Functions**:
- `extract_secrets()` - Find credentials, API keys, paths, etc.
- `detect_base64()` - Decode base64 strings
- `detect_hex_strings()` - Decode hex-encoded strings
- `extract_iocs()` - Get URLs, IPs, domains, emails, hashes

### 5. **dashboard.py** - Web UI Visualization
- Flask-based dashboard
- Real-time analysis results
- Interactive file browser
- Beautiful responsive design

**Key Functions**:
- `start_dashboard()` - Launch Flask server
- `/` - Main dashboard page
- `/api/analysis` - Get analysis JSON
- `/api/files` - List extracted files

### 6. **cli.py** - Unified Command-Line Interface
- **BatchProcessor**: Parallel file processing
- **ReportGenerator**: HTML/JSON/CSV report generation
- **UnifiedCLI**: Main CLI handler

**Commands**:
- `analyze` - Single file analysis
- `batch` - Batch directory processing
- `dashboard` - Start web UI
- `report` - Generate reports

## 🔧 File Signatures Supported (20+)

```
ZIP     .zip    PK\x03\x04
RAR     .rar    Rar!\x1A\x07
7z      .7z     7z\xBC\xAF\x27\x1C
GZIP    .gz     \x1F\x8B\x08
PE      .exe    MZ
BMP     .bmp    BM
PNG     .png    \x89PNG
JPEG    .jpg    \xFF\xD8\xFF
GIF     .gif    GIF8
TIFF    .tiff   II\x2A\x00
WAV     .wav    RIFF
MP3     .mp3    ID3
PDF     .pdf    %PDF
ELF     .elf    \x7FELF
Java    .class  \xCA\xFE\xBA\xBE
```

## 🚀 Quick Start Commands

```bash
# Single file analysis
python cli.py analyze sample.exe

# Full analysis with all options
python cli.py analyze sample.exe --hooks --dotnet -o results/

# Batch process directory
python cli.py batch ./samples *.exe --workers 8

# Start web dashboard
python cli.py dashboard --port 5000

# Generate HTML report
python cli.py report analysis.json report.html

# Run all examples
python examples.py sample.exe --example all
```

## 📊 Output & Reports

### Analysis Report JSON
```json
{
  "basic_info": { "filename", "size", "md5", "sha256", "machine", "sections", "is_dotnet" },
  "security": { "packed", "suspicious_sections", "entropy_levels" },
  "imports": { "dll": ["api1", "api2", ...] },
  "exports": ["func1", "func2", ...],
  "resources": { "total", "by_type" },
  "carved_files": [...],
  "strings": { "ascii_count", "unicode_count", "intelligence" },
  "debug_info": { "has_debug", "entries" },
  "dotnet": { "is_dotnet", "runtime_version", "entry_point" }
}
```

### Dashboard Features
- Binary information card
- Security analysis results
- API imports breakdown
- String intelligence (URLs, IPs)
- Extracted resources list
- File browser for carved files

## 🔍 Analysis Capabilities

### Security Analysis
✓ Packing/encryption detection (entropy analysis)
✓ PE section analysis
✓ Debug information extraction
✓ Code injection patterns
✓ API hook detection
✓ Suspicious import chains
✓ Malware behavior classification

### File Extraction
✓ PE resources (.rsrc)
✓ Signature-based file carving
✓ Embedded executables/DLLs
✓ Compressed archives
✓ Images, audio, documents

### String & Data Extraction
✓ ASCII strings
✓ Unicode strings
✓ URLs and domains
✓ IP addresses
✓ Email addresses
✓ File paths (Windows & UNC)
✓ Registry keys
✓ Cryptographic hashes
✓ Base64 encoded data
✓ Hex encoded data

### Intelligence Extraction
✓ API keys and credentials
✓ Database connection strings
✓ Hardcoded passwords
✓ Cryptocurrency addresses
✓ Private keys and certificates
✓ Configuration files (JSON, XML, INI, YAML)

### .NET Analysis
✓ CLR metadata parsing
✓ Assembly version detection
✓ Runtime version identification
✓ IL code disassembly
✓ Manifest extraction

### Behavioral Analysis
✓ Process injection capabilities
✓ API hooking capabilities
✓ Malware type classification
✓ Suspicious API sequences

## 💡 Usage Patterns

### Pattern 1: Quick Triage
```bash
python cli.py analyze file.exe
# Check dashboard for quick overview
```

### Pattern 2: Deep Investigation
```bash
python cli.py analyze file.exe --hooks --dotnet -o investigation/
python examples.py file.exe --example all
```

### Pattern 3: Threat Intelligence
```python
from config_extractor import SecretExtractorSuite
extractor = SecretExtractorSuite('malware.exe')
iocs = extractor.extract_all()['iocs']
# iocs['urls'], iocs['ips'], iocs['domains'], iocs['emails']
```

### Pattern 4: Batch Processing
```bash
python cli.py batch ./samples *.exe --workers 16
python cli.py report batch_results/batch_results.json report.csv --format csv
```

### Pattern 5: Integration
```python
from decompiler_suite import DecompilerSuite
from api_hook_detector import ImportAnalyzerSuite

suite = DecompilerSuite(file, out_dir)
report = suite.run_full_analysis({...})

analyzer = ImportAnalyzerSuite(file)
api_report = analyzer.run_analysis()

# Combine reports
combined = {**report, 'api_analysis': api_report}
```

## ⚙️ Configuration

### Environment Variables
```bash
export DECOMPILER_OUTPUT_DIR=./my_output
export DECOMPILER_CARVE_MIN_SIZE=256
export DECOMPILER_MAX_WORKERS=8
```

### Dependencies
- pefile: PE file parsing
- capstone: x86/x64 disassembly
- flask: Web dashboard
- requests: HTTP utilities
- jinja2: Template engine

## 🎓 Learning Resources

### Basic Usage
1. Read: `README.md` and `USAGE.md`
2. Run: `python examples.py sample.exe --example 1`
3. Explore: Output files in `decompiled_output/`

### API Usage
1. Check: Module docstrings
2. Review: Example code in `examples.py`
3. Experiment: Modify examples for your needs

### Advanced Techniques
1. Study: Individual module source code
2. Combine: Multiple modules for custom workflows
3. Extend: Add new analysis modules

## 🐛 Debugging

### Enable Debug Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Test Individual Modules
```bash
python decompiler_suite.py test.exe
python api_hook_detector.py test.exe
python config_extractor.py test.exe
```

### Verify Installation
```bash
python -c "import pefile, capstone, flask; print('OK')"
```

## 📈 Performance Metrics

- Single file analysis: 1-10 seconds (depending on size)
- Batch processing: Linear scaling with workers
- File carving: Depends on binary size & file types
- Memory usage: Typically < 500MB per process
- Dashboard startup: < 1 second

## 🔐 Security Considerations

✓ Runs locally - no data sent to external services
✓ No network access required (except optional dashboard)
✓ Handles potentially malicious binaries safely
⚠️ Use isolated environment for unknown binaries
⚠️ Respect confidentiality of extracted secrets
⚠️ Only analyze authorized files

## 📚 Module Dependencies Graph

```
cli.py
├── decompiler_suite.py
│   ├── pefile
│   └── capstone
├── api_hook_detector.py
│   └── pefile
├── config_extractor.py (no external deps)
├── dotnet_analyzer.py (no external deps)
└── dashboard.py
    ├── flask
    └── jinja2

examples.py → all modules
```

## 🎯 Common Workflows

### Malware Analysis
1. `python cli.py analyze malware.exe --hooks --dotnet`
2. Check dashboard for initial triage
3. `python examples.py malware.exe --example 5` (secrets)
4. Investigate extracted IOCs
5. Generate report: `python cli.py report ... report.html`

### Incident Response
1. Batch analyze collected samples: `python cli.py batch ./samples *.exe`
2. Filter by hash in CSV report
3. Extract IOCs for threat intel platform
4. Correlate with MISP/threat feeds

### Reverse Engineering
1. Extract resources and strings
2. Analyze imports and exports
3. View disassembly in dashboard
4. Carve embedded files for deeper analysis

### Quality Assurance
1. Analyze signed binaries: check certs
2. Scan for embedded test/debug files
3. Verify resources
4. Check for unexpected dependencies

## 📞 Support & Issues

### Common Problems & Solutions
- Module import errors → `pip install -r requirements.txt`
- Port in use → `python cli.py dashboard --port 8080`
- Memory issues → Use `--no-carve` or reduce `--workers`
- Slow processing → Increase `--workers` or use SSD

### Resources
- Code examples: `examples.py`
- Usage guide: `USAGE.md`
- Module help: `python -m pydoc module_name`

---

**Version**: 1.0  
**Last Updated**: December 2025  
**Status**: Production Ready  
**Author**: Advanced Binary Analysis Suite