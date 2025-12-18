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
    print(f"  Entropy Levels: {packing['entropy_levels']}")

    imports = SecurityAnalyzer.extract_imports(pe)
    print(f"\nImports by DLL:")
    for dll, apis in list(imports.items())[:3]:
        print(f"  {dll}: {len(apis)} APIs")
        print(f"    {', '.join(apis[:3])}...")

    exports = SecurityAnalyzer.extract_exports(pe)
    if exports:
        print(f"\nExports: {len(exports)} functions")
        print(f"  {', '.join(exports[:5])}...")


def example_api_hook_detection(exe_path: str):
    """Advanced example: API hook and malware behavior detection"""
    print("\n" + "="*60)
    print("EXAMPLE 3: API Hooks & Malware Behavior")
    print("="*60)
    
    analyzer = ImportAnalyzerSuite(exe_path)
    report = analyzer.run_analysis()

    if report['suspicious']['injection_capable']:
        print("⚠️  SUSPICIOUS: Binary has process injection capabilities")
    
    if report['suspicious']['hooking_capable']:
        print("⚠️  SUSPICIOUS: Binary has API hooking capabilities")

    if report['hook_chains']:
        print("\nDetected Hook Chains:")
        for chain in report['hook_chains']:
            print(f"  {chain['chain']}")

    print("\nBehavior Analysis:")
    for behavior, info in report['behavior_analysis'].items():
        if info['matches'] > 0:
            print(f"  {behavior.upper()}: {info['matches']} indicators")


def example_file_carving(exe_path: str):
    """File carving example: Extract embedded files"""
    print("\n" + "="*60)
    print("EXAMPLE 4: File Carving & Extraction")
    print("="*60)

    with open(exe_path, 'rb') as f:
        data = f.read()

    carver = CarvingEngine(data)

    findings = carver.find_signatures()
    print(f"\nFound {len(findings)} file signatures:")
    
    for offset, sig, ext in findings[:10]:
        print(f"  0x{offset:x}: {ext} ({sig.hex()[:20]}...)")

    out_dir = "example_output_carved"
    results = carver.carve_files(out_dir)
    print(f"\nCarved {len(results)} files to {out_dir}")


def example_secret_extraction(exe_path: str):
    """Secret extraction example: Find credentials and configs"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Secret & Config Extraction")
    print("="*60)
    
    extractor = SecretExtractorSuite(exe_path)
    results = extractor.extract_all()

    total_secrets = sum(len(v) for v in results['secrets'].values())
    print(f"\nSecrets Found: {total_secrets}")
    
    for secret_type, findings in results['secrets'].items():
        if findings:
            print(f"  {secret_type}: {len(findings)} instances")
            for finding in findings[:2]:
                print(f"    - {finding['value'][:60]}...")
    
    print(f"\nIndicators of Compromise:")
    iocs = results['iocs']
    print(f"  URLs: {len(iocs['urls'])}")
    print(f"  IPs: {len(iocs['ips'])}")
    print(f"  Domains: {len(iocs['domains'])}")
    print(f"  Emails: {len(iocs['emails'])}")

    creds = results['credentials']
    if creds:
        print(f"\nCredential Indicators:")
        for category, items in creds.items():
            if items:
                print(f"  {category}: {len(items)} found")


def example_dotnet_analysis(exe_path: str):
    """Advanced example: .NET assembly analysis"""
    print("\n" + "="*60)
    print("EXAMPLE 6: .NET Assembly Analysis")
    print("="*60)
    
    decompiler = DotNetDecompiler(exe_path)
    results = decompiler.decompile()
    
    metadata = results['metadata']
    print(f"\n.NET Binary: {metadata['is_dotnet']}")
    
    if metadata['is_dotnet']:
        print(f"Runtime Version: {metadata['runtime_version']}")
        print(f"Entry Point: 0x{metadata['entry_point']:x}")


def example_batch_processing(directory: str):
    """Batch example: Process multiple files"""
    print("\n" + "="*60)
    print("EXAMPLE 7: Batch Processing")
    print("="*60)
    
    from cli import BatchProcessor
    
    processor = BatchProcessor("example_output_batch")

    exe_files = list(Path(directory).glob("*.exe"))
    print(f"\nFound {len(exe_files)} EXE files")

    for exe_file in exe_files[:3]:
        print(f"\nProcessing: {exe_file.name}")
        result = processor.process_file(str(exe_file))
        print(f"  Status: {result['status']}")


def example_custom_workflow(exe_path: str):
    """Custom workflow: Combine multiple modules"""
    print("\n" + "="*60)
    print("EXAMPLE 8: Custom Combined Workflow")
    print("="*60)
    
    out_dir = "example_output_custom"
    os.makedirs(out_dir, exist_ok=True)
    
    with open(exe_path, 'rb') as f:
        binary_data = f.read()
    
    print("\n1. Quick Security Check...")
    import pefile
    pe = pefile.PE(exe_path)
    security = SecurityAnalyzer.detect_packing(pe)
    print(f"   Packed: {security['packed']}")
    
    print("\n2. Extracting Resources...")
    res_dir = os.path.join(out_dir, "resources")
    resources = ResourceExtractor.extract_all_resources(exe_path, res_dir)
    print(f"   Extracted: {resources['total']} resources")
    
    print("\n3. Carving Embedded Files...")
    carver = CarvingEngine(binary_data)
    carvings = carver.carve_files(os.path.join(out_dir, "carved"))
    print(f"   Carved: {len(carvings)} files")
    
    print("\n4. Extracting Strings & Intelligence...")
    strings = StringExtractor.extract_strings(binary_data)
    unicode_strings = StringExtractor.extract_unicode_strings(binary_data)
    urls_ips = StringExtractor.extract_urls_and_ips(strings + unicode_strings)
    print(f"   Strings: {len(strings)} ASCII, {len(unicode_strings)} Unicode")
    print(f"   URLs: {len(urls_ips['urls'])}, IPs: {len(urls_ips['ips'])}")
    
    print("\n5. Analyzing APIs & Behavior...")
    analyzer = ImportAnalyzerSuite(exe_path)
    analysis = analyzer.run_analysis()
    print(f"   Imports: {len(analysis['imports'])} DLLs")
    if analysis['suspicious']['injection_capable']:
        print("   ⚠️  Injection capable")
    
    print("\n6. Extracting Secrets...")
    secret_extractor = SecretExtractorSuite(exe_path)
    secrets = secret_extractor.extract_all()
    total_secrets = sum(len(v) for v in secrets['secrets'].values())
    print(f"   Secrets found: {total_secrets}")
    
    print(f"\n✓ Complete analysis saved to {out_dir}")


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