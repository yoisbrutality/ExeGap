# Usage Guide

Detailed examples and use cases.

## Getting Started

```bash
pip install -r requirements.txt
```

## Basic Analysis

### Analyze a Single File

```bash
# Simple analysis
python main.py analyze target.exe

# With output directory
python main.py analyze target.exe -o results/

# Detect API hooks
python main.py analyze target.exe --hooks

# Extract secrets and configuration
python main.py analyze target.exe --config

# Carve embedded files
python main.py analyze target.exe --carve

# .NET assembly analysis
python main.py analyze target.exe --dotnet

# Everything at once
python main.py analyze target.exe --hooks --config --carve --dotnet --format html
```

## Batch Processing

Analyze multiple files at once:

```bash
# All .exe files in directory
python main.py batch ./samples *.exe

# All binaries
python main.py batch ./samples *

# Speed it up with parallel workers
python main.py batch ./samples *.exe --workers 4

# Custom output
python main.py batch ./samples *.exe -o results/
```

## Interfaces

### GUI (Recommended for Individual Files)

```bash
python main.py gui
```

The GUI lets you:
- Browse and select files
- Choose which analyses to run
- View results in real-time
- Export reports

### Web Dashboard (Great for Sharing)

```bash
python main.py dashboard --port 5000
```

Then open http://localhost:5000 in your browser.

Features:
- Upload files via web
- Real-time analysis
- Download results
- Beautiful interface

### CLI (Best for Scripts)

```bash
python main.py analyze target.exe --hooks --config
```

## Understanding Results

### Output Files

After analysis, you'll see:

```
analysis_results/
├── analysis_report.json      # Full data (machine-readable)
├── analysis_report.html      # Pretty HTML report
├── analysis_report.csv       # Spreadsheet format
└── carved/                   # Extracted files (if --carve used)
    ├── archive.zip
    ├── image.png
    └── ...
```

### Report Contents

The JSON report includes:

```json
{
  "filename": "target.exe",
  "size": 12345,
  "md5": "...",
  "sha256": "...",
  "packed": true,
  "imports": {
    "kernel32.dll": ["CreateProcess", "WriteMemory", ...],
    ...
  },
  "suspicious_apis": [
    "WinExec",
    "CreateRemoteThread",
    ...
  ],
  "secrets_found": {
    "api_keys": ["..."],
    "credentials": ["..."],
    "urls": ["..."]
  },
  ...
}
```

## Common Use Cases

### 1. Quick Security Check

```bash
python main.py analyze target.exe --hooks --config

# Opens analysis_results/analysis_report.html
```

### 2. Analyze a Collection of Samples

```bash
python main.py batch ./malware_samples *.exe --workers 8
```

### 3. Extract Embedded Files

```bash
python main.py analyze target.exe --carve

# Check analysis_results/carved/ for extracted files
```

### 4. Find Configuration/Secrets

```bash
python main.py analyze target.exe --config

# Results show: API keys, URLs, credentials, etc.
```

### 5. Analyze .NET Application

```bash
python main.py analyze app.exe --dotnet
```

### 6. Generate Professional Report

```bash
# HTML report
python main.py analyze target.exe --format html

# Or CSV for spreadsheets
python main.py analyze target.exe --format csv

# Or all formats
python main.py analyze target.exe --format all
```

## Python Integration

Use ExeGap programmatically:

```python
from src.core.pe_analyzer import PEAnalyzer
from src.core.security_analyzer import SecurityAnalyzer

# Analyze PE file
analyzer = PEAnalyzer('target.exe')
pe_info = analyzer.analyze()

print(f"Imports: {len(pe_info['imports'])}")
print(f"Sections: {pe_info['sections']}")

# Security analysis
security = SecurityAnalyzer('target.exe')
report = security.analyze()

if report['dangerous_imports']:
    print("⚠️ Dangerous APIs detected")
```

## Configuration

Edit `config/exegap.json`:

```json
{
  "analysis": {
    "carve_files": true,
    "detect_packing": true,
    "extract_strings": true,
    "analyze_dotnet": true
  },
  "output": {
    "directory": "analysis_results",
    "formats": ["json", "html"]
  }
}
```

## Tips & Tricks

1. **Speed up batch analysis**: Use more workers
   ```bash
   python main.py batch ./samples *.exe --workers 8
   ```

2. **Only what you need**: Disable unused features in config
   ```json
   {"carve_files": false, "analyze_dotnet": false}
   ```

3. **Export for sharing**: Generate HTML report
   ```bash
   python main.py analyze target.exe --format html
   ```

4. **Automated analysis**: Create a script
   ```bash
   for file in *.exe; do
     python main.py analyze "$file" -o "results/$file"
   done
   ```

5. **Integration**: Use JSON output for other tools
   ```bash
   python main.py analyze target.exe --format json
   # Use the JSON with your own tools
   ```

## Troubleshooting

**Analysis is slow**: Try disabling unused features in config

**Out of memory**: Analyze smaller files, use fewer parallel workers

**Can't find results**: Check `analysis_results/` directory

**GUI won't open**: Make sure PyQt5 is installed: `pip install PyQt5`

**Dashboard not responding**: Try a different port: `--port 8080`

For more details, see [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for all commands or [BUILD_GUIDE.md](BUILD_GUIDE.md) to compile to .exe.