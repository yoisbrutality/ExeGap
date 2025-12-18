# 🚀 EXEGAP QUICK START GUIDE

## ⚡ 5-Minute Setup

### Windows Users

1. **Open Command Prompt/PowerShell** in the ExeGap directory

2. **Run the installer**:
   ```powershell
   install.bat
   ```
   
   This automatically:
   - Installs Python dependencies
   - Builds ExeGap.exe
   - Creates standalone executable

3. **Test it works**:
   ```powershell
   ExeGap.exe --help
   ```

### Linux/macOS Users

1. **Open Terminal** in the ExeGap directory

2. **Run the installer**:
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

3. **Test it works**:
   ```bash
   python3 exegap.py --help
   ```

---

## 🎯 Common Tasks

### Launch GUI
```powershell
ExeGap.exe gui
```

### Analyze a File
```powershell
ExeGap.exe analyze sample.exe

# With security analysis
ExeGap.exe analyze sample.exe --hooks

# With .NET analysis
ExeGap.exe analyze sample.exe --dotnet

# Full analysis with all features
ExeGap.exe analyze sample.exe --hooks --dotnet --carve --format all
```

### Batch Process Directory
```powershell
# Analyze all .exe files
ExeGap.exe batch C:\samples\ *.exe

# Use multiple workers for speed
ExeGap.exe batch C:\samples\ *.exe --workers 8
```

### Generate Reports
```powershell
# Create HTML report
ExeGap.exe report results.json report.html --format html

# Create CSV report
ExeGap.exe report results.json report.csv --format csv
```

### Start Web Dashboard
```powershell
ExeGap.exe dashboard

# Custom port
ExeGap.exe dashboard --port 8080
```

---

## 📋 Command Reference

```
ExeGap.exe [COMMAND] [OPTIONS]

COMMANDS:
  analyze       Analyze single binary file
  batch         Process multiple files
  gui           Launch desktop application
  dashboard     Start web interface
  report        Generate analysis report
  --help        Show help message
  --version     Show version

EXAMPLES:
  ExeGap.exe analyze malware.exe
  ExeGap.exe batch ./samples/ *.exe --workers 4
  ExeGap.exe gui
  ExeGap.exe dashboard --port 5000
  ExeGap.exe report analysis.json report.html
```

---

## 🎓 What You Can Do

### 1. Security Analysis
✅ Detect packing/encryption
✅ Identify malware behavior
✅ Find dangerous APIs
✅ Detect process injection

### 2. File Extraction
✅ Carve embedded files
✅ Extract strings
✅ Find hidden resources
✅ Recover lost files

### 3. Binary Understanding
✅ View PE structure
✅ Analyze imports/exports
✅ Study .NET code
✅ Inspect sections

### 4. Batch Operations
✅ Analyze multiple files
✅ Generate mass reports
✅ Create statistics
✅ Find patterns

---

## 📁 Output Structure

After analysis, you'll get:

```
analysis_results/
├── analysis_report.json      # Complete analysis (machine-readable)
├── analysis_report.html      # Beautiful report (browser-friendly)
├── analysis_report.csv       # Spreadsheet data
├── carved/                   # Extracted files
│   ├── ZIP_Archive_001.zip
│   ├── PNG_Image_002.png
│   └── ...
└── metadata/                 # Additional analysis data
```

---

## 🎨 GUI Features

1. **File Selection**: Browse and select executable
2. **Analysis Tab**: View detailed metadata
3. **Security Tab**: Security findings
4. **Results Tab**: Full analysis in JSON
5. **Export**: Save as JSON/HTML
6. **Progress**: Real-time analysis status

---

## ⚙️ Configuration

Edit `config/exegap.json` to customize:

```json
{
  "analysis": {
    "carve_files": true,         # Extract files
    "detect_packing": true,      # Detect compression
    "analyze_dotnet": true,      # .NET support
    "entropy_threshold": 7.5     # Packing sensitivity
  },
  "output": {
    "directory": "analysis_results",
    "formats": ["json", "html"]
  }
}
```

---

## 🆘 Troubleshooting

### Problem: ExeGap.exe not found
**Solution**: Run `install.bat` again to rebuild

### Problem: "Access Denied" error
**Solution**: Run as Administrator
- Right-click → "Run as administrator"

### Problem: GUI won't start
**Solution**: Install PyQt5
```powershell
python -m pip install PyQt5 --upgrade
```

### Problem: Analysis is slow
**Solution**: 
- Use batch processing with multiple workers
- Reduce entropy_threshold in config
- Disable unused features

### Problem: Out of memory
**Solution**:
- Analyze smaller files first
- Reduce parallel workers
- Close other applications

---

## 📊 Output Interpretation

### Security Analysis
- **High Risk**: Multiple dangerous APIs detected
- **Medium Risk**: Some suspicious patterns found
- **Low Risk**: Standard legitimate behavior

### Packing Detection
- **Entropy > 7.5**: Likely packed/compressed
- **Known Packers**: UPX, ASPack, etc.
- **Suspicious Sections**: Unusual segment names

### File Carving
- **Confidence**: How certain we are about file type
- **Offset**: Position in original file (hex)
- **Size**: Approximate file size

---

## 💾 Saving Your Work

### Export Analysis
```powershell
# JSON (complete data)
ExeGap.exe report analysis.json analysis_data.json

# HTML (presentation)
ExeGap.exe report analysis.json report.html

# CSV (spreadsheet)
ExeGap.exe report analysis.json data.csv
```

### Archive Results
```powershell
# ZIP all results
Compress-Archive -Path analysis_results -DestinationPath analysis.zip
```

---

## 🌐 Web Dashboard Usage

1. **Start Dashboard**
   ```powershell
   ExeGap.exe dashboard
   ```

2. **Open Browser**
   ```
   http://localhost:5000
   ```

3. **Upload File**
   - Drag & drop or click to browse
   - Real-time analysis
   - Download results

---

## 📚 Learn More

| Document | Content |
|----------|---------|
| **README.md** | Overview & features |
| **USAGE.md** | Complete commands |
| **BUILD_GUIDE.md** | Build instructions |
| **PROJECT_SUMMARY.md** | Architecture details |

---

## ⭐ Pro Tips

1. **Batch Processing**: Fastest for multiple files
   ```powershell
   ExeGap.exe batch ./samples/ *.exe --workers 8
   ```

2. **Export Chain**: Convert between formats
   ```powershell
   # JSON → HTML → Archive
   ExeGap.exe report analysis.json report.html
   ```

3. **Dashboard**: Best for visual analysis
   ```powershell
   ExeGap.exe dashboard --port 5000
   ```

4. **GUI**: Best for individual file analysis
   ```powershell
   ExeGap.exe gui
   ```

---

## 🔗 Quick Links

- **Help**: `ExeGap.exe --help`
- **Version**: `ExeGap.exe --version`
- **Config**: Edit `config/exegap.json`
- **Logs**: Check console output for details

---

## ✅ Checklist

- [ ] ExeGap installed successfully
- [ ] Tested with `ExeGap.exe --help`
- [ ] Analyzed a test file
- [ ] GUI opens without errors
- [ ] Generated a report
- [ ] Saved results to file

---

## 🎯 Next Steps

1. **Try the GUI**: `ExeGap.exe gui`
2. **Analyze a sample**: `ExeGap.exe analyze sample.exe`
3. **Review reports**: Open generated HTML files
4. **Batch process**: Try `ExeGap.exe batch`
5. **Explore features**: Check USAGE.md

---

**Need help?** Check the documentation files or review command examples above.

**ExeGap 3.0.0** - Professional Binary Analysis Suite
*Ready to analyze!* ✨