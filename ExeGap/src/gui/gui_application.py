#!/usr/bin/env python3
"""
Professional PyQt5 GUI Application
Modern, feature-rich interface for binary analysis
"""
import sys
import json
import os
from pathlib import Path
from threading import Thread
import logging

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QFileDialog, QLabel, QTextEdit, QTableWidget,
        QTableWidgetItem, QTabWidget, QProgressBar, QStatusBar,
        QLineEdit, QComboBox, QCheckBox, QGroupBox, QMessageBox,
        QSplitter, QTreeWidget, QTreeWidgetItem, QHeaderView
    )
    from PyQt5.QtCore import Qt, pyqtSignal, QObject, QThread
    from PyQt5.QtGui import QFont, QIcon, QColor, QPixmap
except ImportError:
    print("PyQt5 not installed. Install with: pip install PyQt5")
    sys.exit(1)

from src.core import PEAnalyzer, SecurityAnalyzer, FileCarver

logger = logging.getLogger(__name__)


class AnalysisWorker(QObject):
    """Worker thread for analysis operations"""
    
    finished = pyqtSignal()
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    result = pyqtSignal(dict)
    
    def __init__(self, filepath: str, analysis_type: str = "full"):
        super().__init__()
        self.filepath = filepath
        self.analysis_type = analysis_type
    
    def run(self):
        """Run analysis"""
        try:
            self.progress.emit("Loading PE file...")
            analyzer = PEAnalyzer(self.filepath)
            
            self.progress.emit("Analyzing metadata...")
            metadata = analyzer.get_metadata()
            
            self.progress.emit("Running security analysis...")
            security = SecurityAnalyzer(analyzer.pe).get_full_security_report()
            
            results = {
                "metadata": metadata.__dict__ if hasattr(metadata, '__dict__') else metadata,
                "security": security,
            }
            
            self.result.emit(results)
            self.progress.emit("Analysis complete!")
        except Exception as e:
            self.error.emit(str(e))
            logger.error(f"Analysis error: {e}")
        finally:
            self.finished.emit()


class ExeGapGUI(QMainWindow):
    """ExeGap Professional GUI Application"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ExeGap - Advanced Binary Analysis Suite")
        self.setGeometry(100, 100, 1400, 900)

        self._setup_ui()
        self._setup_styles()
        self._create_menu_bar()
        
        self.current_file = None
        self.analysis_results = {}
        self.settings = {
            "output_dir": str(Path.home() / "Desktop" / "ExeGap_Results"),
            "auto_save": True,
            "theme": "dark"
        }
    
    def _create_menu_bar(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("📁 File")
        file_menu.addAction("Open File...", self._browse_file)
        file_menu.addAction("Open Results Folder", self._open_results_folder)
        file_menu.addAction("Exit", self.close)

        edit_menu = menubar.addMenu("⚙️ Settings")
        edit_menu.addAction("Preferences", self._show_settings)
        edit_menu.addAction("Output Directory", self._change_output_dir)

        help_menu = menubar.addMenu("❓ Help")
        help_menu.addAction("About", self._show_about)
        help_menu.addAction("Documentation", self._show_docs)
    
    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout()

        file_section = self._create_file_section()
        main_layout.addWidget(file_section)

        tabs = QTabWidget()

        analysis_tab = self._create_analysis_tab()
        tabs.addTab(analysis_tab, "📊 Analysis")

        security_tab = self._create_security_tab()
        tabs.addTab(security_tab, "🛡️ Security")

        results_tab = self._create_results_tab()
        tabs.addTab(results_tab, "📄 Results")
        
        main_layout.addWidget(tabs, 1)

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        
        central_widget.setLayout(main_layout)
    
    def _create_file_section(self) -> QGroupBox:
        """Create file selection section"""
        layout = QHBoxLayout()
        
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Select a PE executable...")
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        
        self.analyze_btn = QPushButton("🔍 Analyze")
        self.analyze_btn.clicked.connect(self._start_analysis)
        self.analyze_btn.setEnabled(False)
        
        layout.addWidget(QLabel("File:"))
        layout.addWidget(self.file_input)
        layout.addWidget(browse_btn)
        layout.addWidget(self.analyze_btn)
        
        group.setLayout(layout)
        return group
    
    def _create_analysis_tab(self) -> QWidget:
        """Create analysis tab"""
        layout = QVBoxLayout()

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.analysis_table = QTableWidget()
        self.analysis_table.setColumnCount(2)
        self.analysis_table.setHorizontalHeaderLabels(["Property", "Value"])
        
        header = self.analysis_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        
        layout.addWidget(self.analysis_table)
        
        widget.setLayout(layout)
        return widget
    
    def _create_security_tab(self) -> QWidget:
        """Create security analysis tab"""
        layout = QVBoxLayout()

        self.security_tree = QTreeWidget()
        self.security_tree.setHeaderLabels(["Finding", "Details"])
        
        layout.addWidget(self.security_tree)
        
        widget.setLayout(layout)
        return widget
    
    def _create_results_tab(self) -> QWidget:
        """Create results tab"""
        layout = QVBoxLayout()

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("Courier", 9))
        
        layout.addWidget(self.results_text)

        button_layout = QHBoxLayout()
        
        json_btn = QPushButton("💾 Export JSON")
        json_btn.clicked.connect(self._export_json)
        
        html_btn = QPushButton("📄 Export HTML")
        html_btn.clicked.connect(self._export_html)
        
        button_layout.addWidget(json_btn)
        button_layout.addWidget(html_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        widget.setLayout(layout)
        return widget
    
    def _setup_styles(self):
        """Setup application styles"""
        QMainWindow {
            background-color: #f0f0f0;
        }
        QGroupBox {
            font-weight: bold;
            border: 2px solid #667eea;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 3px 0 3px;
        }
        QPushButton {
            background-color: #667eea;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #764ba2;
        }
        QPushButton:pressed {
            background-color: #5568d3;
        }
        QTableWidget {
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        QHeaderView::section {
            background-color: #667eea;
            color: white;
            padding: 5px;
            border: none;
        }
        """
        
        self.setStyleSheet(stylesheet)
    
    def _browse_file(self):
        """Browse and select file"""
            self,
            "Select PE Executable",
            "",
            "Executables (*.exe *.dll);;All Files (*)"
        )
        
        if filepath:
            self.file_input.setText(filepath)
            self.current_file = filepath
            self.analyze_btn.setEnabled(True)
            self.statusBar.showMessage(f"Selected: {Path(filepath).name}")
    
    def _start_analysis(self):
        """Start binary analysis"""
            QMessageBox.warning(self, "Error", "Please select a valid file")
            return

        self.analyze_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.statusBar.showMessage("Analyzing...")

        self.worker_thread = QThread()
        self.worker = AnalysisWorker(self.current_file)
        self.worker.moveToThread(self.worker_thread)
        
        self.worker.progress.connect(self._on_progress)
        self.worker.result.connect(self._on_result)
        self.worker.error.connect(self._on_error)
        self.worker.finished.connect(self.worker_thread.quit)
        
        self.worker_thread.started.connect(self.worker.run)
        self.worker_thread.start()
    
    def _on_progress(self, message: str):
        """Handle progress update"""
        self.statusBar.showMessage(message)
    _on_result(self, results: dict):
        """Handle analysis results"""
        self.analysis_results = results
        
        self.analyze_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.statusBar.showMessage("Analysis complete!")
    
    def _on_error(self, error: str):
        """Handle analysis error"""
        QMessageBox.critical(self, "Analysis Error", error)
        self.progress.setVisible(False)
        self.statusBar.showMessage("Error during analysis")
    
    def _display_results(self, results: dict):
        """Display analysis results"""
        self.analysis_table.setRowCount(0)
        self.results_text.clear()

        if "metadata" in results:
            metadata = results["metadata"]
            for key, value in metadata.items():
                row_pos = self.analysis_table.rowCount()
                self.analysis_table.insertRow(row_pos)
                
                self.analysis_table.setItem(row_pos, 0, QTableWidgetItem(str(key)))
                self.analysis_table.setItem(row_pos, 1, QTableWidgetItem(str(value)))

        if "security" in results:
            security = results["security"]

            if "packing_analysis" in security:
                packing = security["packing_analysis"]
                packing_item = QTreeWidgetItem(["Packing Analysis", ""])
                
                for key, value in packing.items():
                    QTreeWidgetItem(packing_item, [str(key), str(value)])
                
                self.security_tree.addTopLevelItem(packing_item)

        self.results_text.setText(json.dumps(results, indent=2, default=str))
    
    def _export_json(self):
        """Export results as JSON"""
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "analysis_report.json",
            "JSON Files (*.json)"
        )
        
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    json.dump(self.analysis_results, f, indent=2, default=str)
                QMessageBox.information(self, "Success", f"Report saved to {filepath}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save report: {e}")
    
    def _open_results_folder(self):
        """Open results folder in file explorer"""
        output_dir = self.settings.get("output_dir", str(Path.home() / "Desktop" / "ExeGap_Results"))
        os.makedirs(output_dir, exist_ok=True)
        import platform
        import subprocess
        
        try:
            if platform.system() == "Windows":
                os.startfile(output_dir)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", output_dir])
            else:
                subprocess.Popen(["xdg-open", output_dir])
            self.statusBar.showMessage(f"Opened folder: {output_dir}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open folder: {e}")
    
    def _change_output_dir(self):
        """Change output directory"""
        directory = QFileDialog.getExistingDirectory(
            self,
            self.settings.get("output_dir", str(Path.home()))
        )
        
        if directory:
            self.settings["output_dir"] = directory
            QMessageBox.information(self, "Settings Updated", f"Output directory set to:\n{directory}")
            self.statusBar.showMessage(f"Output directory: {directory}")
    
    def _show_settings(self):
        """Show settings dialog"""
        msg = f"""ExeGap Settings
═══════════════════════════════
irectory:
  {self.settings.get('output_dir', 'Not set')}

Auto-Save Results:
  {'Enabled' if self.settings.get('auto_save', True) else 'Disabled'}

Theme:
  {self.settings.get('theme', 'dark').capitalize()}

Version: 3.0.0
Quality: Professional/Enterprise Grade

Use menu options to modify settings."""
        QMessageBox.information(self, "Settings", msg)
    
    def _show_about(self):
        """Show about dialog"""
        msg = """ExeGap v3.0.0 - Advanced PE Binary Analysis Suite

Professional-grade binary analysis tool providing:
ary Structure Analysis
✅ Security Threat Detection  
✅ API Hook Detection (6 patterns)
✅ Configuration & Secret Extraction
✅ File Carving & Resource Extraction
✅ .NET Assembly Analysis
✅ Multiple Output Formats

Features: CLI | GUI | Dashboard | Batch Processing

Status: Production Ready | Quality: Enterprise Grade"""
        QMessageBox.information(self, "About ExeGap", msg)
    
    def _show_docs(self):
        """Show documentation"""
        docs_path = Path(__file__).parent.parent.parent / "docs"
        msg = f"""ExeGap Documentation
════════════════════════════════════
: docs/ folder

Quick Start:
  1. Select a PE executable
  2. Click Analyze
  3. View results in tabs
  4. Export as JSON/HTML

Menu Options:
  📁 File - Open/Browse files
  ⚙️ Settings - Configure app
  ❓ Help - View documentation

See docs/ for detailed guides."""
        QMessageBox.information(self, "Documentation", msg)

def main():
    """Main entry point"""
    app = QApplication(sys.argv)
    window = ExeGapGUI()
    window.show()
    

if __name__ == "__main__":
    main()