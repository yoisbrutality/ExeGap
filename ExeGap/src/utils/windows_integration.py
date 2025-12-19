#!/usr/bin/env python3
"""
Windows Integration & System Utilities
Windows-specific features, metadata extraction, and system integration
Consolidated from windows_integration.py
"""
import os
import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
import hashlib
from datetime import datetime
import struct

logger = logging.getLogger(__name__)


class WindowsIntegration:
    """
    Professional Windows integration features
    Version info, digital signatures, file metadata
    """
    
    @staticmethod
    def get_file_version_info(filepath: str) -> Dict[str, str]:
        """Get Windows file version information"""
        try:
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
                    "file_version": info.get('FileVersion', ''),
                    "internal_name": info.get('InternalName', ''),
                    "legal_copyright": info.get('LegalCopyright', ''),
                    "original_filename": info.get('OriginalFilename', ''),
                    "product_version": info.get('ProductVersion', ''),
                }
            except ImportError:
                logger.debug("pywin32 not installed, using fallback method")
                return WindowsIntegration._get_version_info_fallback(filepath)
        except Exception as e:
            logger.error(f"Failed to get version info: {e}")
            return {}
    
    @staticmethod
    def _get_version_info_fallback(filepath: str) -> Dict[str, str]:
        """Fallback method to extract version info from resource section"""
        try:
            import pefile
            pe = pefile.PE(filepath)
            
            info = {"version": "Unknown"}
            
            if hasattr(pe, 'VS_FIXEDFILEINFO'):
                vinfo = pe.VS_FIXEDFILEINFO
                if vinfo:
                    file_version = (vinfo[0].FileVersionMS >> 16, vinfo[0].FileVersionMS & 0xffff,
                                    vinfo[0].FileVersionLS >> 16, vinfo[0].FileVersionLS & 0xffff)
                    info["version"] = ".".join(map(str, file_version))
            
            if hasattr(pe, 'VS_VERSIONINFO'):
                for string_table in pe.VS_VERSIONINFO[0].VarFileInfo[0].StringFileInfo:
                    for string in string_table.StringTable:
                        info.update({
                            "company": string.get('CompanyName', 'Unknown'),
                            "product": string.get('ProductName', 'Unknown'),
                            "description": string.get('FileDescription', ''),
                            "file_version": string.get('FileVersion', ''),
                            "internal_name": string.get('InternalName', ''),
                            "legal_copyright": string.get('LegalCopyright', ''),
                            "original_filename": string.get('OriginalFilename', ''),
                            "product_version": string.get('ProductVersion', ''),
                        })
            
            return info
        except Exception as e:
            logger.debug(f"Fallback version info failed: {e}")
            return {}
    
    @staticmethod
    def get_file_signature(filepath: str) -> Dict[str, str]:
        """Get file digital signature info (requires sigcheck from Sysinternals)"""
        try:
            result = subprocess.run(
                ['sigcheck', '-nobanner', '-j', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    signature_info = {}
                    for line in result.stdout.strip().split('\n'):
                        if ':' in line:
                            key, val = line.split(':', 1)
                            signature_info[key.strip()] = val.strip()
                    return signature_info
        except FileNotFoundError:
            logger.warning("sigcheck tool not found. Download from Sysinternals.")
        except Exception as e:
            logger.debug(f"Signature check failed: {e}")
        
        return {"status": "unsigned or tool not available"}
    
    @staticmethod
    def get_file_metadata(filepath: str) -> Dict[str, any]:
        """Get comprehensive file metadata"""
        if not os.path.exists(filepath):
            return {}
        
        try:
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
        except Exception as e:
            logger.error(f"Failed to get metadata: {e}")
            return {}
    
    @staticmethod
    def check_memory_resident(process_name: str) -> bool:
        """Check if process is running"""
        try:
            import psutil
            return any(p.info['name'] == process_name for p in psutil.process_iter(['name']))
        except ImportError:
            logger.debug("psutil not installed")
            return False
        except Exception as e:
            logger.debug(f"Failed to check process: {e}")
            return False
    
    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Get Windows system information"""
        try:
            import platform
            import socket
            
            return {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "hostname": socket.gethostname(),
                "python_version": platform.python_version(),
            }
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {}


class SystemAnalyzer:
    """
    System-level binary analysis
    Performs targeted analysis on Windows executables
    """
    
    @staticmethod
    def analyze_pe_for_windows(filepath: str) -> Dict[str, any]:
        """Comprehensive Windows PE analysis"""
        try:
            import pefile
            
            pe = pefile.PE(filepath)
            analysis = {
                "file": filepath,
                "machine_type": hex(pe.FILE_HEADER.Machine),
                "subsystem": hex(pe.OPTIONAL_HEADER.Subsystem),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "base_of_code": hex(pe.OPTIONAL_HEADER.BaseOfCode),
            }
            return analysis
        except Exception as e:
            logger.error(f"PE analysis failed: {e}")
            return {"error": str(e)}
    
    @staticmethod
    def check_compatibility(filepath: str) -> Dict[str, any]:
        """Check PE compatibility"""
        try:
            import pefile
            
            pe = pefile.PE(filepath)
            
            compatibility = {
                "compatible": True,
                "warnings": [],
            }

            if pe.OPTIONAL_HEADER.CheckSum == 0:
                compatibility["warnings"].append("No checksum (possible tampering)")
            
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                compatibility["warnings"].append("No imports directory (might be packed or malform)")
            
            if len(compatibility["warnings"]) > 0:
                compatibility["compatible"] = False
            
            return compatibility
        except Exception as e:
            return {"compatible": False, "error": str(e)}


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python windows_integration.py <PE_FILE>")
        sys.exit(1)
    
    analyzer = SystemAnalyzer()
    analysis = analyzer.analyze_pe_for_windows(sys.argv[1])
    print(json.dumps(analysis, indent=2, default=str))
