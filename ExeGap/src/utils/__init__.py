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
                loaded = json.load(f)
                self._merge_dict(self.config, loaded)
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
    
    def _merge_dict(self, target: Dict, source: Dict):
        """Recursive dict merge"""
        for key, value in source.items():
            if isinstance(value, dict) and key in target and isinstance(target[key], dict):
                self._merge_dict(target[key], value)
            else:
                target[key] = value
    
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
                value = value.get(k)
                if value is None:
                    return default
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
                    padding: 40px 30px;
                    text-align: center;
                }
                .header h1 {
                    font-size: 32px;
                    margin-bottom: 10px;
                }
                .header p {
                    font-size: 18px;
                    opacity: 0.9;
                }
                .content {
                    padding: 30px;
                }
                .section {
                    margin-bottom: 40px;
                }
                h2 {
                    color: #667eea;
                    font-size: 24px;
                    margin-bottom: 20px;
                    border-bottom: 2px solid #eee;
                    padding-bottom: 10px;
                }
                .info-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                }
                .info-card {
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    border-left: 4px solid #667eea;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
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
            html += '<div class="section"><h2>📋 File Metadata</h2>'
            html += '<div class="info-grid">'
            for key, value in self.analysis["metadata"].items():
                if key not in ["characteristics"]:
                    html += f'<div class="info-card"><strong>{key.capitalize()}:</strong> {str(value)}</div>'
            html += '</div></div>'
        
        if "pe_analysis" in self.analysis:
            html += '<div class="section"><h2>📁 PE Analysis</h2>'
            html += '<table><tr><th>Property</th><th>Value</th></tr>'
            for key, value in self.analysis["pe_analysis"].items():
                html += f'<tr><td>{key.capitalize()}</td><td>{json.dumps(value, default=str)}</td></tr>'
            html += '</table></div>'
        
        if "security_analysis" in self.analysis:
            security = self.analysis["security_analysis"]
            risk_level = security.get("overall_risk", "low")
            risk_class = f"risk-{risk_level}"
            html += f'<div class="section"><h2>🛡️ Security Analysis</h2>'
            html += f'<div class="info-card {risk_class}">'
            html += f'<strong>Risk Level:</strong> {risk_level.upper()}<br>'
            html += f'<strong>Score:</strong> {security.get("risk_score", 0)}<br>'
            html += '</div>'
            html += '<table><tr><th>Category</th><th>Details</th></tr>'
            for key, value in security.items():
                html += f'<tr><td>{key.capitalize()}</td><td>{json.dumps(value, default=str)}</td></tr>'
            html += '</table></div>'
        
        html += """
                </div>
                <div class="footer">
                    <p>Generated by ExeGap - Advanced Binary Analysis Suite</p>
                    <p>Timestamp: {datetime.now().isoformat()}</p>
                </div>
            </div>
        </body>
        </html>
        """.format(datetime=datetime)
        
        return html
    
    def to_csv(self, filename: str = "report.csv") -> str:
        """Generate CSV report"""
        import csv
        output_path = os.path.join(self.output_dir, filename)
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Category", "Key", "Value"])
                
                if "metadata" in self.analysis:
                    for key, value in self.analysis["metadata"].items():
                        writer.writerow(["Metadata", key, str(value)])
                
                if "security" in self.analysis:
                    for key, value in self.analysis["security"].items():
                        writer.writerow(["Security", key, json.dumps(value, default=str)])
            
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
