"""
Utility modules and helpers
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ConfigManager:
    """Configuration management"""
    
    DEFAULT_CONFIG = {
        "analysis": {
            "carve_files": True,
            "extract_strings": True,
            "detect_packing": True,
            "analyze_dotnet": True,
            "check_imports": True,
        },
        "output": {
            "directory": "analysis_results",
            "format": ["json", "html", "csv"],
        },
        "ui": {
            "theme": "dark",
            "port": 5000,
        }
    }
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file
        self.config = self.DEFAULT_CONFIG.copy()
        
        if config_file and os.path.exists(config_file):
            self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                self.config.update(json.load(f))
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
    
    def save_config(self):
        """Save configuration to file"""
        if not self.config_file:
            return
        
        try:
            os.makedirs(os.path.dirname(self.config_file) or '.', exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def get(self, key: str, default: Any = None):
        """Get config value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        
        return value


class ReportGenerator:
    """Generate analysis reports in multiple formats"""
    
    def __init__(self, analysis_data: Dict[str, Any], output_dir: str = "reports"):
        self.analysis = analysis_data
        self.output_dir = output_dir
        
        os.makedirs(output_dir, exist_ok=True)
    
    def to_json(self, filename: str = "report.json") -> str:
        """Generate JSON report"""
        output_path = os.path.join(self.output_dir, filename)
        
        try:
            with open(output_path, 'w') as f:
                json.dump(self.analysis, f, indent=2, default=str)
            logger.info(f"JSON report saved: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return None
    
    def to_html(self, filename: str = "report.html") -> str:
        """Generate HTML report"""
        output_path = os.path.join(self.output_dir, filename)
        
        html_content = self._generate_html()
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report saved: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return None
    
    def _generate_html(self) -> str:
        """Generate HTML content"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ExeGap Binary Analysis Report</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: #333;
                    padding: 20px;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }
                .header h1 {
                    font-size: 2.5em;
                    margin-bottom: 10px;
                }
                .content {
                    padding: 30px;
                }
                .section {
                    margin-bottom: 30px;
                    border-left: 4px solid #667eea;
                    padding-left: 20px;
                }
                .section h2 {
                    color: #667eea;
                    margin-bottom: 15px;
                    font-size: 1.8em;
                }
                .info-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 20px;
                }
                .info-card {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    border-left: 3px solid #667eea;
                }
                .info-card strong {
                    color: #667eea;
                }
                .risk-high {
                    background: #ffe6e6;
                    border-left-color: #d32f2f;
                }
                .risk-medium {
                    background: #fff4e6;
                    border-left-color: #f57c00;
                }
                .risk-low {
                    background: #e6ffe6;
                    border-left-color: #388e3c;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 10px;
                }
                th, td {
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background: #667eea;
                    color: white;
                    font-weight: 600;
                }
                tr:hover {
                    background: #f5f5f5;
                }
                .footer {
                    background: #f8f9fa;
                    padding: 20px;
                    text-align: center;
                    color: #666;
                    border-top: 1px solid #ddd;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 ExeGap Binary Analysis Report</h1>
                    <p>Professional PE Binary Analysis & Decompilation Suite</p>
                </div>
                <div class="content">
        """
        
        if "metadata" in self.analysis:
            html += "<div class='section'><h2>📋 File Metadata</h2>"
            html += "<div class='info-grid'>"
            for key, value in self.analysis["metadata"].items():
                if key not in ["characteristics"]:
                    html += f"<div class='info-card'><strong>{key}:</strong> {value}</div>"
            html += "</div></div>"
        
        if "packing_analysis" in self.analysis:
            packing = self.analysis["packing_analysis"]
            risk_class = f"risk-{packing.get('risk_level', 'low')}"
            html += f"<div class='section'><h2>🛡️ Security Analysis</h2>"
            html += f"<div class='info-card {risk_class}'>"
            html += f"<strong>Packing Status:</strong> {'Detected' if packing.get('packed') else 'Not Detected'}<br>"
            html += f"<strong>Risk Level:</strong> {packing.get('risk_level', 'Unknown').upper()}<br>"
            html += "</div></div>"
        
        html += """
                </div>
                <div class="footer">
                    <p>Generated by ExeGap - Advanced Binary Analysis Suite</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def to_csv(self, filename: str = "report.csv") -> str:
        """Generate CSV report"""
        import csv
        output_path = os.path.join(self.output_dir, filename)
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.analysis.get("metadata", {}).keys())
                writer.writeheader()
                writer.writerow(self.analysis.get("metadata", {}))
            
            logger.info(f"CSV report saved: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return None


class Logger:
    """Centralized logging"""
    
    @staticmethod
    def setup_logging(log_file: str = None, level=logging.INFO):
        """Setup logging"""
        handlers = [logging.StreamHandler()]
        
        if log_file:
            handlers.append(logging.FileHandler(log_file))
        
        logging.basicConfig(
            level=level,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            handlers=handlers
        )


__all__ = ['ConfigManager', 'ReportGenerator', 'Logger']
