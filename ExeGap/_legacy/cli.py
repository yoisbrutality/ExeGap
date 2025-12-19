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
        if not files:
            logger.warning("No files found matching pattern")
            return []
        
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.process_file, str(f)) for f in files]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        
        return results


class ReportGenerator:
    """Generate reports from analysis results"""
    
    @staticmethod
    def generate_html_report(data: Dict, output_file: str):
        """Generate HTML report"""
        html = "<html><body><pre>" + json.dumps(data, indent=2, default=str) + "</pre></body></html>"
        with open(output_file, 'w') as f:
            f.write(html)
        logger.info(f"HTML report generated: {output_file}")
    
    @staticmethod
    def generate_json_report(data: Dict, output_file: str):
        """Generate JSON report"""
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"JSON report generated: {output_file}")


class UnifiedCLI:
    """Unified CLI interface"""
    
    @staticmethod
    def main():
        parser = argparse.ArgumentParser(
            description="EXE Decompiler Suite - Unified CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  cli.py analyze sample.exe
  cli.py analyze sample.exe --dotnet
  cli.py batch /samples/
  cli.py dashboard --port 8080
  cli.py report results.json report.html --format html
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', required=True)
        
        analyze_parser = subparsers.add_parser('analyze', help='Analyze single binary')
        analyze_parser.add_argument('file', help='PE file to analyze')
        analyze_parser.add_argument('-o', '--out', default='analysis_results', help='Output directory')
        analyze_parser.add_argument('--hooks', action='store_true', help='Detect API hooks')
        analyze_parser.add_argument('--dotnet', action='store_true', help='Analyze .NET')
        analyze_parser.add_argument('--dashboard', action='store_true', help='Launch dashboard')
        
        batch_parser = subparsers.add_parser('batch', help='Batch process binaries')
        batch_parser.add_argument('directory', help='Directory to process')
        batch_parser.add_argument('--pattern', default='*.exe', help='File pattern')
        batch_parser.add_argument('-o', '--out', default='batch_results', help='Output directory')
        batch_parser.add_argument('--workers', type=int, default=4, help='Number of workers')
        
        dashboard_parser = subparsers.add_parser('dashboard', help='Launch web dashboard')
        dashboard_parser.add_argument('--port', type=int, default=5000, help='Port')
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
