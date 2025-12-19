#!/usr/bin/env python3
"""
Complete Example & Tutorial for EXE Decompiler Suite
Shows how to use each module independently or together
"""
import os
import json
from pathlib import Path

from decompiler_suite import (
    DecompilerSuite, SecurityAnalyzer, CarvingEngine, 
    ResourceExtractor, ConfigExtractor as StringExtractor
)
from api_hook_detector import ImportAnalyzerSuite, APIHookDetector
from dotnet_analyzer import DotNetDecompiler
from config_extractor import SecretExtractorSuite
from dashboard import start_dashboard


def example_basic_analysis(exe_path: str):
    """Basic example: Analyze a single binary"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Analysis")
    print("="*60)

    out_dir = "example_output_basic"
    os.makedirs(out_dir, exist_ok=True)

    suite = DecompilerSuite(exe_path, out_dir)
    report = suite.run_full_analysis({
        "security": True,
        "resources": True,
        "carve": True,
        "strings": True,
        "dotnet": True,
        "debug": True
    })

    print(f"\nFile: {report['basic_info']['filename']}")
    print(f"Size: {report['basic_info']['size']} bytes")
    print(f"MD5: {report['basic_info']['md5']}")
    
    if report['security']['packed']:
        print(f"⚠️  PACKED: {report['security']['suspicious_sections']}")
    else:
        print("✓ Not packed")
    
    print(f"Sections: {report['basic_info']['sections']}")
    print(f"Resources extracted: {report['resources']['total']}")
    print(f"Imports: {len(report['imports'])} DLLs")
    print(f"Strings found: {report['strings']['ascii_count']} ASCII + {report['strings']['unicode_count']} Unicode")


def example_security_analysis(exe_path: str):
    """Intermediate example: Deep security analysis"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Security & Behavior Analysis")
    print("="*60)
    
    import pefile
    
    pe = pefile.PE(exe_path)

    packing = SecurityAnalyzer.detect_packing(pe)
    print(f"\nPacking Detection:")
    print(f"  Packed: {packing['packed']}")
    print(f"  Suspicious Sections: {packing['suspicious_sections']}")


def example_api_hook_detection(exe_path: str):
    """API hook detection example"""
    print("\n" + "="*60)
    print("EXAMPLE 3: API Hook Detection")
    print("="*60)
    
    analyzer = ImportAnalyzerSuite(exe_path)
    report = analyzer.run_analysis()
    
    print(f"Hook Detection: {report['hook_detection']['hooked']}")
    print("Patterns Found:")
    for pattern in report['hook_detection']['patterns_found']:
        print(f"  - {pattern['type']} at {hex(pattern['offset'])}")


def example_file_carving(exe_path: str):
    """File carving example"""
    print("\n" + "="*60)
    print("EXAMPLE 4: File Carving")
    print("="*60)
    
    with open(exe_path, 'rb') as f:
        data = f.read()
    
    engine = CarvingEngine(data, "carved_output")
    engine.carve_all()
    summary = engine.get_summary()
    
    print(f"Total Found: {summary['total_found']}")
    print("File Types:")
    for ftype, count in summary['file_types'].items():
        print(f"  - {ftype}: {count}")


def example_secret_extraction(exe_path: str):
    """Secret extraction example"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Secret Extraction")
    print("="*60)
    
    extractor = SecretExtractorSuite(exe_path)
    results = extractor.extract_all()
    
    print(f"Secrets Found: {len(results['secrets'])}")
    for secret in results['secrets'][:5]:
        print(f"  - {secret['type']}: {secret['value'][:20]}...")


def example_dotnet_analysis(exe_path: str):
    """ .NET analysis example"""
    print("\n" + "="*60)
    print("EXAMPLE 6: .NET Analysis")
    print("="*60)
    
    decompiler = DotNetDecompiler(exe_path)
    results = decompiler.decompile()
    
    print(f"CLR Version: {results['metadata'].get('clr_version', 'Unknown')}")
    print(f"Manifest Found: {results['manifest']['found']}")


def example_custom_workflow(exe_path: str):
    """Custom workflow example"""
    print("\n" + "="*60)
    print("EXAMPLE 8: Custom Workflow")
    print("="*60)
    
    out_dir = "custom_analysis"
    os.makedirs(out_dir, exist_ok=True)

    ResourceExtractor.extract_resources(exe_path, out_dir)

    with open(exe_path, 'rb') as f:
        data = f.read()
    CarvingEngine.carve_all(data, out_dir)

    extractor = StringExtractor()
    strings = extractor.extract_strings(data)
    secrets = extractor.find_secrets(data)
    
    import pefile
    pe = pefile.PE(exe_path)
    packing = SecurityAnalyzer.detect_packing(pe)

    custom_report = {
        "strings": strings,
        "secrets": secrets,
        "packing": packing
    }
    
    with open(os.path.join(out_dir, "custom_report.json"), 'w') as f:
        json.dump(custom_report, f, indent=2)
    
    print(f"\n✓ Custom analysis saved to {out_dir}")


def example_batch_processing(directory: str):
    """Batch processing example"""
    print("\n" + "="*60)
    print("EXAMPLE 7: Batch Processing")
    print("="*60)
    
    files = list(Path(directory).glob("*.exe"))
    results = []
    
    for file in files:
        suite = DecompilerSuite(str(file), f"batch_{file.stem}")
        report = suite.run_full_analysis()
        results.append({
            "file": str(file),
            "packed": report["security"]["packed"]
        })
    
    print(f"Processed {len(results)} files")
    print(json.dumps(results, indent=2))


def main():
    """Run examples"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="EXE Decompiler Suite - Complete Examples",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python examples.py path/to/sample.exe --example 1
  python examples.py path/to/sample.exe --example all
  python examples.py /samples/directory --batch
        """
    )
    
    parser.add_argument('target', help='EXE file or directory')
    parser.add_argument('--example', default='1', help='Example number (1-8 or all)')
    parser.add_argument('--batch', action='store_true', help='Batch processing mode')
    
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: {args.target} not found")
        return
    
    if args.batch and os.path.isdir(args.target):
        example_batch_processing(args.target)
    elif os.path.isfile(args.target):
        examples = {
            '1': example_basic_analysis,
            '2': example_security_analysis,
            '3': example_api_hook_detection,
            '4': example_file_carving,
            '5': example_secret_extraction,
            '6': example_dotnet_analysis,
            '8': example_custom_workflow,
        }
        
        if args.example == 'all':
            for num in ['1', '2', '3', '4', '5', '6', '8']:
                try:
                    examples[num](args.target)
                except Exception as e:
                    print(f"\n❌ Example {num} error: {e}")
        else:
            if args.example in examples:
                try:
                    examples[args.example](args.target)
                except Exception as e:
                    print(f"\n❌ Error: {e}")
            else:
                print(f"Unknown example: {args.example}")
    
    print("\n" + "="*60)
    print("✓ Examples complete!")
    print("="*60)


if __name__ == '__main__':
    main()
