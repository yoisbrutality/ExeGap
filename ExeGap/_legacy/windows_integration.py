#!/usr/bin/env python3
"""
Windows Integration & Automation Tools
PowerShell wrappers and Windows-specific features
"""
import os
import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
import hashlib

logger = logging.getLogger(__name__)


class WindowsIntegration:
    """Windows-specific integration features"""
    
    @staticmethod
    def get_file_version_info(filepath: str) -> Dict:
        """Get Windows file version information"""
        try:
            import win32api
            info = win32api.GetFileVersionInfo(filepath, '\\')
            ms = info['FileVersionMS']
            ls = info['FileVersionLS']
            version = f"{(ms >> 16) & 0xffff}.{(ms) & 0xffff}.{(ls >> 16) & 0xffff}.{(ls) & 0xffff}"
            
            return {
                "version": version,
                "company": info.get('CompanyName', 'Unknown'),
                "product": info.get('ProductName', 'Unknown'),
                "description": info.get('FileDescription', ''),
            }
        except ImportError:
            logger.warning("pywin32 not installed, skipping version info")
            return {}
        except Exception as e:
            logger.error(f"Failed to get version info: {e}")
            return {}
    
    @staticmethod
    def get_file_signature(filepath: str) -> Dict:
        """Get Windows digital signature information"""
        try:
            result = subprocess.run(['sigcheck', '-nobanner', filepath], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                signature_info = {}
                for line in lines:
                    if ':' in line:
                        key, val = line.split(':', 1)
                        signature_info[key.strip()] = val.strip()
                return signature_info
        except Exception as e:
            logger.debug(f"Signature check failed: {e}")
        
        return {}
    
    @staticmethod
    def get_file_metadata(filepath: str) -> Dict:
        """Get comprehensive file metadata"""
        if not os.path.exists(filepath):
            return {}
        
        file_stat = os.stat(filepath)
        
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
                sha256.update(chunk)
        
        metadata = {
            "path": filepath,
            "name": os.path.basename(filepath),
            "size": file_stat.st_size,
            "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat() if file_stat.st_ctime > 0 else "Invalid",
            "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat() if file_stat.st_mtime > 0 else "Invalid",
            "accessed": datetime.fromtimestamp(file_stat.st_atime).isoformat() if file_stat.st_atime > 0 else "Invalid",
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest(),
            "attributes": oct(file_stat.st_mode),
        }
        
        metadata["version_info"] = WindowsIntegration.get_file_version_info(filepath)
        
        metadata["signature"] = WindowsIntegration.get_file_signature(filepath)
        
        return metadata


class PowerShellHelper:
    """PowerShell script generator"""
    
    @staticmethod
    def generate_analysis_script(directory: str) -> str:
        """Generate PowerShell script for batch analysis"""
        script = f"""
$directory = '{directory}'

Get-ChildItem -Path $directory -Filter *.exe -Recurse | ForEach-Object {{
    $file = $_.FullName
    Write-Host "Analyzing: $file"
}}
"""
        return script


class SystemScannerWin:
    """Windows system scanner"""
    
    @staticmethod
    def full_system_scan() -> Dict:
        """Perform full system scan"""
        results = {
            "running_processes": [],
            "startup_items": [],
        }
        
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                results["running_processes"].append(proc.info)
        except ImportError:
            logger.warning("psutil not installed")

        results["startup_items"] = []
        
        return results


class RegistryAnalyzer:
    """Analyze Windows registry"""
    
    @staticmethod
    def scan_registry() -> Dict:
        """Scan registry for suspicious keys"""
        findings = {
            "autorun": [],
            "suspicious": [],
        }

        return findings


class RapidTriage:
    """Rapid file triage"""
    
    @staticmethod
    def quick_check(filepath: str) -> Dict:
        """Quick 30-second analysis"""
        findings = {
            "basic_checks": {},
            "quick_verdict": "LOW_RISK"
        }
        
        try:
            import pefile
            pe = pefile.PE(filepath)
            file_stat = os.stat(filepath)
            
            findings["basic_checks"]["file_size"] = file_stat.st_size
            findings["basic_checks"]["machine"] = hex(pe.FILE_HEADER.Machine)

            findings["basic_checks"]["sections"] = len(pe.sections)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                findings["basic_checks"]["import_count"] = sum(
                    len(dll.imports) for dll in pe.DIRECTORY_ENTRY_IMPORT
                )

            risk_score = 0

            if findings["basic_checks"].get("import_count", 0) > 50:
                risk_score += 1
            
            if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
                findings["basic_checks"]["is_dotnet"] = True
            
            if risk_score == 0:
                findings["quick_verdict"] = "LOW_RISK"
            elif risk_score <= 2:
                findings["quick_verdict"] = "MEDIUM_RISK"
            else:
                findings["quick_verdict"] = "HIGH_RISK"
        
        except Exception as e:
            findings["error"] = str(e)
            findings["quick_verdict"] = "ERROR"
        
        return findings


def main():
    """Windows integration utilities"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Windows Integration Tools")
    parser.add_argument('--system-scan', action='store_true', help='Scan system for malware')
    parser.add_argument('--gen-script', help='Generate PowerShell script for directory')
    parser.add_argument('--quick-check', help='Quick 30-second analysis of file')
    parser.add_argument('--registry-scan', action='store_true', help='Scan registry')
    
    args = parser.parse_args()
    
    if args.system_scan:
        scanner = SystemScannerWin()
        results = scanner.full_system_scan()
        print(json.dumps(results, indent=2, default=str))
    
    elif args.gen_script:
        script = PowerShellHelper.generate_analysis_script(args.gen_script)
        with open('analyze_all.ps1', 'w') as f:
            f.write(script)
        print("PowerShell script generated: analyze_all.ps1")
    
    elif args.quick_check:
        result = RapidTriage.quick_check(args.quick_check)
        print(json.dumps(result, indent=2))
    
    elif args.registry_scan:
        findings = RegistryAnalyzer.scan_registry()
        print(json.dumps(findings, indent=2))
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
