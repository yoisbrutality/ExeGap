#!/usr/bin/env python3
"""
ExeGap Professional Unified CLI Interface
Advanced binary analysis and decompilation toolkit
"""
import argparse
import sys
import os
import json
import logging
from pathlib import Path
from typing import List, Dict
import concurrent.futures

from src.core import PEAnalyzer, SecurityAnalyzer, FileCarver, DotNetHandler, ConfigExtractor
from src.utils import ConfigManager, ReportGenerator, Logger

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class ExeGapCLI:
    """Unified CLI interface"""
    
    def __init__(self):
        self.parser = self._create_parser()
        self.config = ConfigManager("config/exegap.json")
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description="ExeGap - Advanced Binary Analysis & Decompilation Suite",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s analyze sample.exe
  %(prog)s analyze sample.exe -o results/ --hooks --dotnet
  %(prog)s batch ./samples/ *.exe --workers 8
  %(prog)s gui
  %(prog)s dashboard --port 8080
            """
        )
        
        parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Enable verbose output"
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Commands")
        
        analyze_parser = subparsers.add_parser("analyze", help="Analyze single binary")
        analyze_parser.add_argument("file", help="PE executable file")
        analyze_parser.add_argument(
            "-o", "--out",
            default="analysis_results",
            help="Output directory"
        )
        analyze_parser.add_argument(
            "--hooks",
            action="store_true",
            help="Detect API hooks"
        )
        analyze_parser.add_argument(
            "--dotnet",
            action="store_true",
            help="Analyze .NET assemblies"
        )
        analyze_parser.add_argument(
            "--carve",
            action="store_true",
            help="Carve embedded files"
        )
        analyze_parser.add_argument(
            "--config",
            action="store_true",
            help="Extract configuration and secrets"
        )
        analyze_parser.add_argument(
            "--format",
            choices=["json", "html", "csv", "all"],
            default="json",
            help="Report format"
        )
        
        batch_parser = subparsers.add_parser("batch", help="Batch process binaries")
        batch_parser.add_argument("directory", help="Directory containing binaries")
        batch_parser.add_argument(
            "pattern",
            nargs="?",
            default="*.exe",
            help="File pattern (default: *.exe)"
        )
        batch_parser.add_argument(
            "-o", "--out",
            default="batch_results",
            help="Output directory"
        )
        batch_parser.add_argument(
            "--workers",
            type=int,
            default=4,
            help="Number of parallel workers"
        )
        
        gui_parser = subparsers.add_parser("gui", help="Launch GUI")
        gui_parser.add_argument(
            "--theme",
            choices=["dark", "light"],
            default="dark",
            help="UI theme"
        )
        
        dashboard_parser = subparsers.add_parser("dashboard", help="Launch web dashboard")
        dashboard_parser.add_argument(
            "--port",
            type=int,
            default=5000,
            help="Port to listen on"
        )
        dashboard_parser.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug mode"
        )
        
        report_parser = subparsers.add_parser("report", help="Generate report")
        report_parser.add_argument("output", help="Output report file")
        report_parser.add_argument(
            "--format",
            choices=["html", "json", "csv"],
            default="html",
            help="Report format"
        )
        
        return parser
    
    def run(self):
        """Run CLI"""
        args = self.parser.parse_args()
        
        if not args.command:
            self.parser.print_help()
            return 0
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        try:
            if args.command == "analyze":
                return self._analyze(args)
            elif args.command == "batch":
                return self._batch(args)
            elif args.command == "gui":
                return self._gui(args)
            elif args.command == "dashboard":
                return self._dashboard(args)
            elif args.command == "report":
                return self._report(args)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            return 130
        except Exception as e:
            logger.error(f"Error: {e}")
            return 1
    
    def _analyze(self, args) -> int:
        """Analyze single binary"""
        if not os.path.exists(args.file):
            logger.error(f"File not found: {args.file}")
            return 1
        
        os.makedirs(args.out, exist_ok=True)
        
        logger.info(f"Analyzing: {args.file}")
        
        try:
            with open(args.file, 'rb') as f:
                binary_data = f.read()
            analyzer = PEAnalyzer(args.file)
            pe_analysis = analyzer.get_full_analysis()
            
            logger.info("Running security analysis...")
            security_analyzer = SecurityAnalyzer(analyzer.pe)
            security_analysis = security_analyzer.get_full_security_report()
            
            results = {
                "file": args.file,
                "timestamp": __import__('datetime').datetime.now().isoformat(),
                "pe_analysis": pe_analysis,
                "security_analysis": security_analysis,
            }
            
            if args.dotnet:
                logger.info("Running .NET analysis...")
                dotnet = DotNetHandler(args.file)
                if dotnet.is_dotnet_assembly():
                    results["dotnet_analysis"] = dotnet.get_full_analysis()

            if args.carve:
                logger.info("Carving embedded files...")
                carver = FileCarver(binary_data, os.path.join(args.out, "carved"))
                results["carved_files"] = carver.get_summary()

            if args.config:
                logger.info("Extracting configuration and secrets...")
                config_extractor = ConfigExtractor(args.file)
                config_extractor.extract_from_binary(binary_data)
                results["configuration_extraction"] = config_extractor.get_report()
            
            output_file = os.path.join(args.out, "analysis_report.json")
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Analysis saved to: {output_file}")
            
            gen = ReportGenerator(results, args.out)
            
            if args.format in ["html", "all"]:
                gen.to_html("analysis_report.html")
            
            if args.format in ["csv", "all"]:
                logger.info("Generating CSV report...")
                gen.to_csv("analysis_report.csv")
            
            logger.info("Analysis complete!")
            return 0
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return 1
    
    def _batch(self, args) -> int:
        """Batch process binaries"""
        if not os.path.isdir(args.directory):
            logger.error(f"Directory not found: {args.directory}")
            return 1
        
        os.makedirs(args.out, exist_ok=True)
        
        files = list(Path(args.directory).glob(args.pattern))
        logger.info(f"Found {len(files)} files matching {args.pattern}")
        
        if not files:
            logger.warning("No files found")
            return 1
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(self._analyze_file, str(f), args.out): f
                for f in files
            }
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"[{i}/{len(files)}] Completed: {Path(result['file']).name}")
                except Exception as e:
                    logger.error(f"Error processing file: {e}")
        
        batch_report = os.path.join(args.out, "batch_report.json")
        with open(batch_report, 'w') as f:
            json.dump({"total": len(files), "analyzed": len(results), "results": results}, f, indent=2, default=str)
        
        logger.info(f"Batch analysis complete! Report: {batch_report}")
        
    def _analyze_file(self, filepath: str, output_dir: str) -> Dict:
        """Analyze single file for batch processing"""
        try:
            analyzer = PEAnalyzer(filepath)
            security = SecurityAnalyzer(analyzer.pe)
            
            return {
                "file": filepath,
                "status": "success",
                "metadata": analyzer.get_metadata().__dict__,
                "security": security.get_full_security_report(),
            }
        except Exception as e:
            return {
                "file": filepath,
                "status": "error",
                "error": str(e)
            }
    
    def _gui(self, args) -> int:
        """Launch GUI application"""
        try:
            from src.gui.gui_application import main
            main()
            return 0
        except ImportError:
            logger.error("PyQt5 not installed. Install with: pip install PyQt5")
            return 1
        except Exception as e:
            logger.error(f"GUI error: {e}")
            return 1
    
    def _dashboard(self, args) -> int:
        """Start web dashboard"""
        try:
            logger.info(f"Starting dashboard on http://localhost:{args.port}")
            logger.info("Press Ctrl+C to stop")
            
            from flask import Flask, render_template_string, jsonify, request
            
            app = Flask(__name__)
            
            @app.route('/')
            def index():
                return render_template_string(self._get_dashboard_html())
            
            @app.route('/api/analyze', methods=['POST'])
            def analyze():
                data = request.json
                return jsonify({"status": "ok"})
            
            app.run(host='localhost', port=args.port, debug=args.debug)
            return 0
        except ImportError:
            logger.error("Flask not installed. Install with: pip install flask")
            return 1
        except Exception as e:
            logger.error(f"Dashboard error: {e}")
            return 1
    
    def _report(self, args) -> int:
        """Generate reports"""
        if not os.path.exists(args.input):
            logger.error(f"File not found: {args.input}")
            return 1
        
        try:
            with open(args.input, 'r') as f:
                data = json.load(f)
            
            output_dir = os.path.dirname(args.output) or "."
            gen = ReportGenerator(data, output_dir)
            
            if args.format == "html":
                gen.to_html(os.path.basename(args.output))
            elif args.format == "json":
                gen.to_json(os.path.basename(args.output))
            elif args.format == "csv":
                gen.to_csv(os.path.basename(args.output))
            
            logger.info(f"Report saved to: {args.output}")
            return 0
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return 1
    
    def _get_dashboard_html(self) -> str:
        """Get dashboard HTML"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>ExeGap Dashboard</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                    padding: 40px;
                }
                h1 { color: #667eea; margin-bottom: 30px; }
                .upload-box {
                    border: 2px dashed #667eea;
                    border-radius: 10px;
                    padding: 30px;
                    text-align: center;
                    cursor: pointer;
                }
                button {
                    background: #667eea;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-weight: bold;
                }
                button:hover { background: #764ba2; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔍 ExeGap Dashboard</h1>
                <div class="upload-box">
                    <p>Drag and drop your executable here or click to browse</p>
                    <input type="file" id="fileInput" accept=".exe,.dll">
                </div>
            </div>
        </body>
        </html>
        """


def main():
    """Main entry point"""
    cli = ExeGapCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
