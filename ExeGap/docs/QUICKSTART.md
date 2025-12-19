# Quick Start

Get running in 5 minutes.

## Install & Run

```bash
# Install dependencies
pip install -r requirements.txt

# Analyze a file
python main.py analyze target.exe

# Or use the GUI
python main.py gui
```

## Common Commands

```bash
# Detect API hooks
python main.py analyze file.exe --hooks

# Extract secrets (API keys, credentials, URLs)
python main.py analyze file.exe --config

# Carve embedded files
python main.py analyze file.exe --carve

# Analyze .NET assemblies
python main.py analyze file.exe --dotnet

# Full analysis
python main.py analyze file.exe --hooks --config --carve --dotnet --format html

# Process multiple files
python main.py batch ./samples *.exe --workers 4

# Web dashboard
python main.py dashboard --port 5000
```

## Build as .exe

```bash
python build_exe.py
# Creates ExeGap.exe in current directory
```

## Results

Your analysis goes into `analysis_results/`:
- `analysis_report.json` - Full analysis data
- `analysis_report.html` - Pretty report
- `carved/` - Any embedded files found

Done. See [USAGE.md](USAGE.md) for more details.