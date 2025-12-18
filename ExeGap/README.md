# ExeGap

Binary analysis tool for Windows PE executables.

## What It Does

- **Analyze PE files** - Structure, imports, exports, resources
- **Detect API hooks** - Find suspicious code modifications
- **Extract secrets** - API keys, credentials, URLs, wallets
- **Carve files** - Extract embedded files
- **Analyze .NET** - Inspect .NET assemblies
- **Generate reports** - JSON, HTML, CSV formats

## Quick Start

```bash
pip install -r requirements.txt

python main.py analyze sample.exe

```

Or use the GUI:

```bash
python main.py gui
```

## Common Commands

```bash
python main.py analyze file.exe --hooks --config --carve --dotnet --format html

python main.py batch ./samples *.exe --workers 4

python main.py dashboard --port 5000

python main.py report analysis.json report.html --format html
```

## Documentation

- **[Quick Start](docs/QUICKSTART.md)** - 5 minute setup
- **[Usage Guide](docs/USAGE.md)** - Detailed examples
- **[Commands](docs/QUICK_REFERENCE.md)** - All commands
- **[Build .exe](docs/BUILD_GUIDE.md)** - Compile to standalone
- **[Folder Structure](docs/FOLDER_STRUCTURE.md)** - How code is organized
- **[Full Index](docs/INDEX.md)** - All documentation

## Features

### Analysis
- PE binary structure
- Import/export analysis
- Packing detection
- Entropy calculation
- String extraction

### Security
- API hook detection (6 patterns)
- Code injection analysis
- Behavior classification
- Risk scoring

### Extraction
- 40+ file type signatures
- Embedded file carving
- Resource extraction
- .NET assembly analysis

### Interfaces
- CLI (command line)
- GUI (PyQt5 desktop)
- Web dashboard (Flask)

## Installation

Python 3.8+ required.

```bash
pip install -r requirements.txt
```

## Usage

### Analyze a File
```bash
python main.py analyze target.exe
```

### Detect Hooks
```bash
python main.py analyze target.exe --hooks
```

### Extract Secrets
```bash
python main.py analyze target.exe --config
```

### Carve Embedded Files
```bash
python main.py analyze target.exe --carve
```

### Use the GUI
```bash
python main.py gui
```

### Web Dashboard
```bash
python main.py dashboard --port 5000
```

### Batch Process
```bash
python main.py batch ./samples *.exe --workers 4
```

## Build as .exe

```bash
python build_exe.py
```

This creates a standalone `ExeGap.exe` that doesn't need Python installed.

## Project Structure

```
src/core/           - Analysis modules
src/gui/            - Desktop interface
src/web/            - Web dashboard
src/utils/          - Utilities
config/             - Configuration
docs/               - Documentation
_legacy/            - Old scripts (archived)
main.py             - Main entry point
build_exe.py        - Build automation
```

## Results

After analysis, check `analysis_results/`:

- `analysis_report.json` - Full data
- `analysis_report.html` - Pretty report
- `analysis_report.csv` - Spreadsheet format
- `carved/` - Extracted files

## Examples

See [docs/USAGE.md](docs/USAGE.md) for detailed examples, or [docs/QUICK_REFERENCE.md](docs/QUICK_REFERENCE.md) for all commands.

## License

See LICENSE file for details.

## Quick Links

- Start: [Quick Start Guide](docs/QUICKSTART.md)
- Learn: [Usage Guide](docs/USAGE.md)
- Build: [Build Guide](docs/BUILD_GUIDE.md)
- Help: [All Commands](docs/QUICK_REFERENCE.md)
- **Status**: Production Ready
- **Quality**: Enterprise Grade

## 📝 License

Professional Binary Analysis Suite

## 🤝 Support

For detailed information, see:
- Technical Details: [docs/CONSOLIDATION_REPORT.md](docs/CONSOLIDATION_REPORT.md)
- Feature Inventory: [docs/PROJECT_COMPLETION_STATUS.md](docs/PROJECT_COMPLETION_STATUS.md)
- Commands Reference: [docs/QUICK_REFERENCE.md](docs/QUICK_REFERENCE.md)

---

**Get Started**: `python main.py --help`

**Build Executable**: `python build_exe.py`

**Read Docs**: Check the `docs/` folder