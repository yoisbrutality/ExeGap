#!/usr/bin/env python3
"""
Professional PyQt5 GUI Application
Modern, feature-rich interface for binary analysis
"""
import sys
import json
import os
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QTextEdit, QTableWidget,
    QTableWidgetItem, QTabWidget, QProgressBar, QStatusBar,
    QLineEdit, QComboBox, QCheckBox, QGroupBox, QMessageBox,
    QSplitter, QTreeWidget, QTreeWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QIcon, QColor, QPixmap
import logging

from src.core import PEAnalyzer, SecurityAnalyzer, FileCarver, DotNetHandler

logger = logging.getLogger(__name__)


class AnalysisWorker(QThread):
    """Worker thread for analysis operations"""
    
    finished = pyqtSignal()
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    result = pyqtSignal(dict)
    
    def __init__(self, filepath: str, options: dict):
        super().__init__()
        self.filepath = filepath
        self.options = options
    
    def run(self):
        """Run analysis"""
        try:
            self.progress.emit("Loading PE file...")
            analyzer = PEAnalyzer(self.filepath)
            
            self.progress.emit("Analyzing metadata...")
            metadata = analyzer.get_full_analysis()
            
            self.progress.emit("Running security analysis...")
            binary_data = open(self.filepath, 'rb').read()
            security = SecurityAnalyzer(analyzer.pe).get_full_security_report(binary_data)
            
            results = {
                "metadata": metadata,
                "security": security,
            }
            
            if self.options.get("carve", False):
                self.progress.emit("Carving files...")
                carver = FileCarver(binary_data)
                carver.carve_all()
                results["carving"] = carver.get_summary()
            
            if self.options.get("dotnet", False):
                self.progress.emit("Analyzing .NET...")
                dotnet = DotNetHandler(self.filepath)
                if dotnet.is_dotnet_assembly():
                    results["dotnet"] = dotnet.get_full_analysis()
            
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
        group = QGroupBox("Binary Selection")
        layout = QVBoxLayout()
        
        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Select a PE executable...")
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)
        
        options_group = QGroupBox("Analysis Options")
        options_layout = QHBoxLayout()
        
        self.hooks_check = QCheckBox("Detect API Hooks")
        self.dotnet_check = QCheckBox("Analyze .NET")
        self.carve_check = QCheckBox("Carve Embedded Files")
        self.config_check = QCheckBox("Extract Secrets")
        
        options_layout.addWidget(self.hooks_check)
        options_layout.addWidget(self.dotnet_check)
        options_layout.addWidget(self.carve_check)
        options_layout.addWidget(self.config_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        self.analyze_btn = QPushButton("🔍 Analyze")
        self.analyze_btn.clicked.connect(self._start_analysis)
        self.analyze_btn.setEnabled(False)
        layout.addWidget(self.analyze_btn)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        group.setLayout(layout)
        return group
    
    def _create_analysis_tab(self) -> QWidget:
        """Create analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        self.analysis_table = QTableWidget(0, 2)
        self.analysis_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.analysis_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.analysis_table)
        widget.setLayout(layout)
        return widget
    
    def _create_security_tab(self) -> QWidget:
        """Create security tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        self.security_tree = QTreeWidget()
        self.security_tree.setHeaderLabels(["Category", "Details"])
        self.security_tree.setColumnWidth(0, 300)
        
        layout.addWidget(self.security_tree)
        widget.setLayout(layout)
        return widget
    
    def _create_results_tab(self) -> QWidget:
        """Create results tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        export_layout = QHBoxLayout()
        export_json_btn = QPushButton("Export JSON")
        export_json_btn.clicked.connect(self._export_json)
        
        export_html_btn = QPushButton("Export HTML")
        export_html_btn.clicked.connect(self._export_html)
        
        export_layout.addWidget(export_json_btn)
        export_layout.addWidget(export_html_btn)
        
        layout.addLayout(export_layout)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("Courier", 10))
        
        layout.addWidget(self.results_text)
        widget.setLayout(layout)
        return widget
    
    def _setup_styles(self):
        """Setup application styles"""
        if self.settings["theme"] == "dark":
            self.setStyleSheet("""
                QMainWindow { background-color: #1e1e1e; color: #ffffff; }
                QGroupBox { border: 1px solid #3a3a3a; border-radius: 5px; background-color: #252526; }
                QPushButton { background-color: #0d6efd; color: white; border-radius: 5px; padding: 5px; }
                QPushButton:hover { background-color: #0b5ed7; }
                QLineEdit { background-color: #333333; color: #ffffff; border: 1px solid #3a3a3a; }
                QTextEdit { background-color: #1e1e1e; color: #d4d4d4; border: 1px solid #3a3a3a; }
                QTableWidget { background-color: #252526; color: #ffffff; gridline-color: #3a3a3a; }
                QHeaderView::section { background-color: #3a3a3a; color: #ffffff; }
                QTreeWidget { background-color: #252526; color: #ffffff; }
                QProgressBar { background-color: #3a3a3a; color: #ffffff; border: 1px solid #3a3a3a; }
                QProgressBar::chunk { background-color: #0d6efd; }
            """)
    
    def _browse_file(self):
        """Browse for PE file"""
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Select PE Executable",
            "",
            "Executables (*.exe *.dll);;All Files (*)"
        )
        
        if filepath:
            self.file_input.setText(filepath)
            self.current_file = filepath
