#!/usr/bin/env python3
"""
Unified CLI Interface - Main entry point for all decompiler tools
Supports batch processing, reporting, and integration
"""
import argparse
import sys
import os
import json
import logging
from pathlib import Path
from typing import List, Dict
import concurrent.futures

from decompiler_suite import DecompilerSuite
from api_hook_detector import ImportAnalyzerSuite
from dotnet_analyzer import DotNetDecompiler
from dashboard import start_dashboard

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class BatchProcessor:
    """Process multiple files in batch"""
    
    def __init__(self, output_dir: str = "batch_analysis"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def process_file(self, filepath: str, analysis_type: str = "full") -> Dict:
        """Process a single file"""
        logger.info(f"Processing: {filepath}")
        
        results = {
            "file": filepath,
            "status": "processing",
            "analyses": {}
        }
        
        try:
            if analysis_type in ["full", "suite"]:
                out_subdir = os.path.join(self.output_dir, Path(filepath).stem)
                suite = DecompilerSuite(filepath, out_subdir)
                results["analyses"]["decompiler"] = suite.run_full_analysis({
                    "security": True,
                    "resources": True,
                    "carve": True,
                    "strings": True,
                    "dotnet": True,
                    "debug": True
                })
            
            if analysis_type in ["full", "api"]:
                hook_analyzer = ImportAnalyzerSuite(filepath)
                results["analyses"]["api_hooks"] = hook_analyzer.run_analysis()
            
            results["status"] = "success"
        except Exception as e:
            logger.error(f"Error processing {filepath}: {e}")
            results["status"] = "error"
            results["error"] = str(e)
        
        return results
    
    def process_directory(self, directory: str, pattern: str = "*.exe", max_workers: int = 4) -> List[Dict]:
        """Process all files in a directory"""
        logger.info(f"Processing directory: {directory}")
        
        files = list(Path(directory).glob(pattern))
        logger.info(f"Found {len(files)} files matching {pattern}")
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.process_file, str(f)): f for f in files}
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error in batch processing: {e}")
        
        return results


class ReportGenerator:
    """Generate comprehensive analysis reports"""
    
    @staticmethod
    def generate_html_report(analysis_results: Dict, output_file: str = "report.html"):
        """Generate HTML report from analysis results"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Binary Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .report { background: white; padding: 20px; border-radius: 5px; }
                h1 { color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }
                h2 { color: #667eea; margin-top: 20px; }
                .section { margin: 20px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #667eea; }
                .alert { padding: 10px; margin: 10px 0; border-radius: 5px; }
                .alert-danger { background: #f8d7da; color: #721c24; }
                .alert-warning { background: #fff3cd; color: #856404; }
                .alert-success { background: #d4edda; color: #155724; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background: #667eea; color: white; }
                code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
            </style>
        </head>
        <body>
            <div class="report">
                <h1>Binary Analysis Report</h1>
                <p>Generated report for binary analysis.</p>
                <div class="section">
                    <h2>Analysis Summary</h2>
                    <pre>{}</pre>
                </div>
            </div>
        </body>
        </html>
        """.format(json.dumps(analysis_results, indent=2, default=str))
        
        with open(output_file, 'w') as f:
            f.write(html_template)
        
        logger.info(f"HTML report saved to {output_file}")
    
    @staticmethod
    def generate_json_report(analysis_results: Dict, output_file: str = "report.json"):
        """Generate JSON report"""
        with open(output_file, 'w') as f:
            json.dump(analysis_results, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to {output_file}")
    
    @staticmethod
    def generate_csv_report(batch_results: List[Dict], output_file: str = "report.csv"):
        """Generate CSV report for batch analysis"""
        import csv
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["file", "status", "md5", "packed", "imports"])
            writer.writeheader()
            
            for result in batch_results:
                if result['status'] == 'success':
                    basic = result['analyses'].get('decompiler', {}).get('basic_info', {})
                    security = result['analyses'].get('decompiler', {}).get('security', {})
                    imports = result['analyses'].get('api_hooks', {}).get('imports', {})
                    
                    writer.writerow({
                        "file": result['file'],
                        "status": result['status'],
                        "md5": basic.get('md5', ''),
                        "packed": security.get('packed', False),
                        "imports": len(imports)
                    })
        
        logger.info(f"CSV report saved to {output_file}")


class UnifiedCLI:
    """Main CLI interface"""
    
    @staticmethod
    def main():
        parser = argparse.ArgumentParser(
            description='Advanced EXE Decompiler & Extractor Suite',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python cli.py analyze sample.exe

  python cli.py analyze sample.exe --hooks

  python cli.py batch /path/to/samples *.exe

  python cli.py dashboard

  python cli.py report analysis_output report.html
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command to run')
        
        analyze_parser = subparsers.add_parser('analyze', help='Analyze a single binary')
        analyze_parser.add_argument('file', help='Binary file to analyze')
        analyze_parser.add_argument('-o', '--out', default='decompiled_output', help='Output directory')
        analyze_parser.add_argument('--hooks', action='store_true', help='Run API hook detection')
        analyze_parser.add_argument('--dotnet', action='store_true', help='Run .NET analysis')
        analyze_parser.add_argument('--dashboard', action='store_true', help='Start dashboard after analysis')
        
        batch_parser = subparsers.add_parser('batch', help='Batch process files')
        batch_parser.add_argument('directory', help='Directory to process')
        batch_parser.add_argument('pattern', nargs='?', default='*.exe', help='File pattern')
        batch_parser.add_argument('-o', '--out', default='batch_analysis', help='Output directory')
        batch_parser.add_argument('--workers', type=int, default=4, help='Number of workers')
        
        dashboard_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
        dashboard_parser.add_argument('--port', type=int, default=5000, help='Port to run on')
        dashboard_parser.add_argument('--debug', action='store_true', help='Debug mode')
        
        report_parser = subparsers.add_parser('report', help='Generate reports')
        report_parser.add_argument('input', help='Analysis results JSON or directory')
        report_parser.add_argument('output', help='Output report file')
        report_parser.add_argument('--format', choices=['html', 'json', 'csv'], default='html')
        
        args = parser.parse_args()
        
        if args.command == 'analyze':
            logger.info(f"Analyzing {args.file}")
            suite = DecompilerSuite(args.file, args.out)
            report = suite.run_full_analysis({
                "security": True,
                "resources": True,
                "carve": True,
                "strings": True,
                "dotnet": args.dotnet,
                "debug": True
            })
            
            if args.hooks:
                logger.info("Running API hook detection...")
                hook_analyzer = ImportAnalyzerSuite(args.file)
                hook_report = hook_analyzer.run_analysis()
                report['api_analysis'] = hook_report
            
            if args.dashboard:
                start_dashboard()
            else:
                print(json.dumps(report, indent=2, default=str))
        
        elif args.command == 'batch':
            processor = BatchProcessor(args.out)
            results = processor.process_directory(args.directory, args.pattern, args.workers)
            
            with open(os.path.join(args.out, 'batch_results.json'), 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            logger.info(f"Batch processing complete. Results saved to {args.out}")
        
        elif args.command == 'dashboard':
            start_dashboard(port=args.port, debug=args.debug)
        
        elif args.command == 'report':
            if os.path.isfile(args.input):
                with open(args.input, 'r') as f:
                    data = json.load(f)
                
                if args.format == 'html':
                    ReportGenerator.generate_html_report(data, args.output)
                elif args.format == 'json':
                    ReportGenerator.generate_json_report(data, args.output)
            else:
                logger.error("Report generation requires a JSON input file")
        
        else:
            parser.print_help()


if __name__ == '__main__':
    UnifiedCLI.main()