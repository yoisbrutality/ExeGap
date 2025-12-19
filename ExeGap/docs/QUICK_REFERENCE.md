# Commands Reference

Basic commands for analyzing PE files.

## Single File Analysis

```bash
# Basic analysis
python main.py analyze target.exe

# With API hook detection
python main.py analyze target.exe --hooks

# Extract secrets (API keys, credentials, etc)
python main.py analyze target.exe --config

# Carve embedded files
python main.py analyze target.exe --carve

# .NET assembly analysis
python main.py analyze target.exe --dotnet

# Full analysis with HTML report
python main.py analyze target.exe --hooks --config --carve --dotnet --format html
```

## Batch Processing

```bash
# Analyze multiple files
python main.py batch ./samples *.exe

# With multiple workers for speed
python main.py batch ./samples *.exe --workers 4

# Custom output directory
python main.py batch ./samples *.exe -o results/
```

## Interfaces

```bash
# Launch GUI
python main.py gui

# Start web dashboard
python main.py dashboard --port 5000

# Generate report from previous analysis
python main.py report analysis.json report.html --format html
```

## Output Formats

```bash
# JSON (full data)
--format json

# HTML (pretty report)
--format html

# CSV (spreadsheet)
--format csv

# All formats
--format all
```

## Output Location

Default: `analysis_results/`

Files created:
- `analysis_report.json` - Full analysis data
- `analysis_report.html` - Pretty HTML report
- `analysis_report.csv` - Spreadsheet data
- `carved/` - Extracted files

To customize output:
```bash
python main.py analyze target.exe -o my_folder/
```

## Options

| Option | Purpose |
|--------|---------|
| `--hooks` | Detect API hooks and suspicious modifications |
| `--config` | Extract secrets and configuration data |
| `--carve` | Extract embedded files |
| `--dotnet` | Analyze .NET assemblies |
| `--format` | Output format (json, html, csv) |
| `-o DIR` | Output directory |

Done. See [USAGE.md](USAGE.md) for detailed examples.
│   ├── __init__.py .................... Config, reports, logging
│   └── windows_integration.py ......... Windows metadata, signatures
├── src/web/
│   └── dashboard.py ................... Web dashboard (Flask)
├── main.py ............................ Unified CLI (NEW HUB)
├── build_exe.py ....................... Build to executable
└── requirements.txt
```

## Legacy Files Status

These can be safely archived (their functionality is now integrated):
- ✅ api_hook_detector.py
- ✅ cli.py  
- ✅ config_extractor.py (now new module)
- ✅ extractor.py
- ✅ windows_integration.py (now new module)

Recommendation: Create `_legacy_backup/` directory to preserve them for reference.

## Getting Started

1. **Install Requirements**
   ```bash
   pip install -r requirements.txt
   ```

2. **Analyze a File**
   ```bash
   python main.py analyze sample.exe -o results/
   ```

3. **Full Analysis**
   ```bash
   python main.py analyze sample.exe -o results/ --hooks --config --carve --dotnet --format html
   ```

4. **Check Results**
   - JSON: `results/analysis_report.json`
   - HTML: `results/analysis_report.html`
   - IOCs: `results/iocs.json` (if --config used)
   - Carved files: `results/carved/`

## Command Reference

```
main.py analyze FILE              Analyze single binary
main.py batch DIR [PATTERN]       Batch process directory
main.py gui [--theme THEME]       Launch GUI application
main.py dashboard [--port PORT]   Start web dashboard
main.py report INPUT OUTPUT       Generate reports
```

## Options

```
analyze:
  -o, --out DIR           Output directory (default: analysis_results)
  --hooks                 Detect API hooks
  --config                Extract secrets/config
  --carve                 Carve embedded files
  --dotnet                Analyze .NET assemblies
  --format FMT            Report format: json|html|csv|all

batch:
  --workers N             Parallel workers (default: 4)
  -o, --out DIR           Output directory

dashboard:
  --port N                Port to listen on (default: 5000)
  --debug                 Enable debug mode
```

## What's New

✨ **API Hook Detection** - Comprehensive hook pattern analysis  
✨ **Secrets Extraction** - Extract credentials, API keys, tokens  
✨ **IOC Generation** - Automatically create indicator files  
✨ **Resource Extraction** - Enhanced PE resource carving  
✨ **Unified Interface** - Single command for all features  
✨ **Windows Metadata** - File signatures, version info, system data  
✨ **Professional Code** - 4000+ lines of enterprise-grade Python  

## Need Help?

```bash
python main.py --help
python main.py analyze --help
python main.py batch --help
```

## Key Files to Know

- **main.py** - Your new unified entry point
- **src/core/security_analyzer.py** - Hook & threat detection
- **src/core/config_extractor.py** - Secrets & config extraction
- **requirements.txt** - Python dependencies
- **CONSOLIDATION_REPORT.md** - Technical consolidation details

---

**Status**: ✅ Ready to use  
**Quality**: Professional/Enterprise grade  
**Features**: Full original + enhancements