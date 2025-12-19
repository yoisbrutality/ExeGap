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
            import win32con
            
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
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
        except ImportError:
            pass
        
        file_stat = os.stat(filepath)
        
        metadata = {
            "path": filepath,
            "name": os.path.basename(filepath),
            "size": file_stat.st_size,
            "created": file_stat.st_ctime,
            "modified": file_stat.st_mtime,
            "accessed": file_stat.st_atime,
            "md5": hashlib.md5(open(filepath, 'rb').read()).hexdigest(),
        }
        
        return metadata


class WindowsEventLogAnalyzer:
    """Analyze Windows Event Logs for binary execution"""
    
    @staticmethod
    def get_process_creation_events(minutes: int = 60) -> List[Dict]:
        """Get process creation events from Windows Event Log"""
        try:
            cmd = f"""
            Get-WinEvent -FilterHashtable @{{
                LogName = 'Security'
                ID = 4688
                StartTime = [DateTime]::Now.AddMinutes(-{minutes})
            }} -ErrorAction SilentlyContinue | 
            Select-Object @{{
                Name = 'Timestamp'; Expression = {{$_.TimeCreated}}
            }}, @{{
                Name = 'ProcessName'; Expression = {{$_.Properties[5].Value}}
            }}, @{{
                Name = 'CommandLine'; Expression = {{$_.Properties[8].Value}}
            }}
            """
            
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', cmd],
                capture_output=True, text=True, timeout=30
            )
            
            events = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    events.append({"event": line})
            
            return events
        except Exception as e:
            logger.error(f"Failed to get process creation events: {e}")
            return []
    
    @staticmethod
    def find_suspicious_processes() -> List[Dict]:
        """Find suspicious process execution patterns"""
        suspicious = []
        
        try:
            suspicious_patterns = [
                'cmd.exe',
                'powershell.exe',
                'rundll32.exe',
                'regsvcs.exe',
                'regasm.exe',
                'mshta.exe',
                'certutil.exe',
                'bitsadmin.exe',
            ]
            
            cmd = """
            Get-Process | 
            Where-Object {{$_.ProcessName -match '(cmd|powershell|rundll32|regsvcs|regasm|mshta|certutil|bitsadmin)'}} |
            Select-Object Name, Id, Path, StartTime
            """
            
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', cmd],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    suspicious.append({"process": line})
        
        except Exception as e:
            logger.debug(f"Failed to find suspicious processes: {e}")
        
        return suspicious


class RegistryAnalyzer:
    """Analyze Windows Registry for malware indicators"""

    SUSPICIOUS_PATHS = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    ]
    
    @staticmethod
    def scan_registry() -> Dict:
        """Scan registry for suspicious entries"""
        findings = {
            "suspicious_runs": [],
            "suspicious_shell_handlers": [],
            "suspicious_services": [],
        }
        
        try:
            import winreg

            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    key = winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Run")
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        if RegistryAnalyzer._is_suspicious_entry(name, value):
                            findings["suspicious_runs"].append({
                                "name": name,
                                "value": value
                            })
                    winreg.CloseKey(key)
                except Exception:
                    pass
        
        except ImportError:
            logger.warning("winreg not available")
        except Exception as e:
            logger.error(f"Registry scan error: {e}")
        
        return findings
    
    @staticmethod
    def _is_suspicious_entry(name: str, value: str) -> bool:
        """Check if registry entry is suspicious"""
        suspicious_keywords = [
            'rundll32',
            'powershell',
            'cmd.exe',
            'mshta',
            'certutil',
            'regsvcs',
            'regasm',
        ]
        
        value_lower = value.lower()
        return any(keyword in value_lower for keyword in suspicious_keywords)


class SystemScannerWin:
    """Comprehensive Windows system scanner"""
    
    def __init__(self, output_dir: str = "windows_scan"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def full_system_scan(self) -> Dict:
        """Perform full system scan for malware indicators"""
        results = {
            "timestamp": None,
            "suspicious_processes": [],
            "registry_findings": {},
            "process_creation_events": [],
            "suspicious_files": [],
        }
        
        import datetime
        results["timestamp"] = datetime.datetime.now().isoformat()
        
        logger.info("Scanning for suspicious processes...")
        results["suspicious_processes"] = WindowsEventLogAnalyzer.find_suspicious_processes()
        
        logger.info("Scanning registry...")
        results["registry_findings"] = RegistryAnalyzer.scan_registry()
        
        logger.info("Analyzing process creation events...")
        results["process_creation_events"] = WindowsEventLogAnalyzer.get_process_creation_events()

        report_path = os.path.join(self.output_dir, "system_scan_report.json")
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Scan complete. Report saved to {report_path}")
        return results
    
    def scan_directory(self, directory: str) -> List[Dict]:
        """Scan directory for suspicious files"""
        suspicious_files = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    if any(skip in filepath.lower() for skip in ['system32', 'syswow64', 'windows']):
                        continue
                    
                    try:
                        file_stat = os.stat(filepath)

                        if self._is_suspicious_file(filepath):
                            suspicious_files.append({
                                "path": filepath,
                                "size": file_stat.st_size,
                                "modified": file_stat.st_mtime,
                            })
                    except Exception as e:
                        logger.debug(f"Error analyzing {filepath}: {e}")
        
        except Exception as e:
            logger.error(f"Directory scan error: {e}")
        
        return suspicious_files
    
    @staticmethod
    def _is_suspicious_file(filepath: str) -> bool:
        """Check if file is suspicious"""
        suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr']
        suspicious_patterns = ['malware', 'virus', 'trojan', 'worm', 'backdoor']
        
        name_lower = os.path.basename(filepath).lower()

        if any(name_lower.endswith(ext) for ext in suspicious_extensions):
            if any(pattern in name_lower for pattern in suspicious_patterns):
                return True
        
        return False


class PowerShellHelper:
    """Helper functions for PowerShell integration"""
    
    @staticmethod
    def generate_analysis_script(target_dir: str, output_dir: str = "analysis") -> str:
        """Generate PowerShell script for batch analysis"""
        script = f"""

$targetDir = "{target_dir}"
$outputDir = "{output_dir}"
$pythonScript = "cli.py"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

$binaries = Get-ChildItem -Path $targetDir -Recurse -Include *.exe, *.dll

Write-Host "Found $($binaries.Count) binaries to analyze"

foreach ($binary in $binaries) {{
    $outPath = Join-Path $outputDir ($binary.BaseName + "_analysis")
    Write-Host "Analyzing: $($binary.Name) -> $outPath"
    
    python $pythonScript analyze "$($binary.FullName)" -o $outPath
}}

Write-Host "Batch analysis complete"
"""
        return script
    
    @staticmethod
    def generate_monitoring_script() -> str:
        """Generate PowerShell script for real-time monitoring"""
        script = """
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $env:USERPROFILE + "\\Downloads"
$watcher.Filter = "*.exe"
$watcher.IncludeSubdirectories = $true

$action = {
    $file = $Event.SourceEventArgs.Name
    $path = $Event.SourceEventArgs.FullPath
    
    Write-Host "New file detected: $file"
    Write-Host "Analyzing with decompiler..."
    
    python cli.py analyze "$path" -o "analysis_$([System.IO.Path]::GetFileNameWithoutExtension($file))"
}

Register-ObjectEvent -InputObject $watcher -EventName "Created" -Action $action

Write-Host "Monitoring enabled. Press Ctrl+C to stop."
while ($true) { Start-Sleep -Seconds 1 }
"""
        return script


class RapidTriage:
    """Rapid triage for quick analysis"""
    
    @staticmethod
    def quick_check(file_path: str) -> Dict:
        """Quick 30-second analysis"""
        findings = {
            "file": file_path,
            "basic_checks": {},
            "quick_verdict": None
        }
        
        try:
            import pefile

            pe = pefile.PE(file_path)

            file_stat = os.stat(file_path)
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
            
            if hasattr(pe, 'DIRECTORY_ENTRY_COM20_HEADER'):
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
