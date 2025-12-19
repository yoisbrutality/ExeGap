#!/usr/bin/env python3
"""
Advanced API Hook Detector & Import Analyzer
Detects API hooks, suspicious imports, and analyzes DLL dependencies
"""
import pefile
import json
import logging
from typing import Dict, List, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class APIHookDetector:
    """Detect common API hooking techniques"""

    HOOK_PATTERNS = {
        "jmp_hook": b"\xFF\x25",
        "call_hook": b"\xE8",
        "int3_hook": b"\xCC",
        "nop_hook": b"\x90\x90",
    }

    SUSPICIOUS_SEQUENCES = [
        ("GetProcAddress", "WriteProcessMemory"),
        ("VirtualAllocEx", "WriteProcessMemory"),
        ("CreateRemoteThread", "WaitForSingleObject"),
        ("SetWindowsHookEx", "GetMessage"),
        ("DLL_PROCESS_ATTACH", "CreateThread"),
    ]
    
    @staticmethod
    def detect_hooks_in_section(pe: pefile.PE, section_name: str = ".text") -> Dict:
        """Detect hooks in a specific section"""
        findings = {
            "hooked": False,
            "patterns_found": [],
            "suspicious_regions": []
        }
        
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if sec_name != section_name:
                continue
            
            code = pe.get_data(section.VirtualAddress, section.SizeOfRawData)
            
            for hook_type, pattern in APIHookDetector.HOOK_PATTERNS.items():
                offset = 0
                while True:
                    offset = code.find(pattern, offset)
                    if offset == -1:
                        break

                    if not APIHookDetector._is_likely_hook(code, offset, pattern):
                        offset += len(pattern)
                        continue
                    
                    findings["hooked"] = True
                    findings["patterns_found"].append({
                        "type": hook_type,
                        "offset": section.VirtualAddress + offset,
                        "pattern": pattern.hex()
                    })
                    offset += len(pattern)
        
        return findings
    
    @staticmethod
    def _is_likely_hook(code: bytes, offset: int, pattern: bytes) -> bool:
        """Heuristic to determine if pattern is likely a hook vs legitimate code"""
        if offset < 16:
            return False

        return True
    
    @staticmethod
    def detect_hook_chains(imports: Dict[str, List[str]]) -> List[Tuple[str, str]]:
        """Detect sequences of imports that suggest hooking"""
        chains = []
        
        for suspect_chain in APIHookDetector.SUSPICIOUS_SEQUENCES:
            api1, api2 = suspect_chain
            found1, found2 = False, False
            dll1, dll2 = None, None
            
            for dll, apis in imports.items():
                if api1 in apis:
                    found1 = True
                    dll1 = dll
                if api2 in apis:
                    found2 = True
                    dll2 = dll
            
            if found1 and found2:
                chains.append({
                    "chain": suspect_chain,
                    "dlls": [dll1, dll2],
                    "severity": "medium"
                })
        
        return chains


class ImportAnalyzer:
    """Analyze imported functions and DLL dependencies"""

    API_CATEGORIES = {
        "process": ["CreateProcessA", "CreateProcessW", "TerminateProcess", "GetCurrentProcess"],
        "memory": ["VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory"],
        "injection": ["CreateRemoteThread", "NtCreateThreadEx", "SetThreadContext"],
        "hooking": ["SetWindowsHookEx", "GetProcAddress", "LoadLibrary"],
        "file_io": ["CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA"],
        "registry": ["RegOpenKeyEx", "RegQueryValueEx", "RegSetValueEx", "RegDeleteKey"],
        "networking": ["socket", "connect", "send", "recv", "WSASocket"],
        "encryption": ["CryptEncrypt", "CryptDecrypt", "CryptCreateHash"],
        "system": ["GetSystemDirectory", "GetWindowsDirectory", "GetEnvironmentVariable"],
    }
    
    @staticmethod
    def categorize_imports(imports: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Categorize imported functions"""
        categorized = defaultdict(list)
        
        for dll, apis in imports.items():
            for api in apis:
                for category, api_list in ImportAnalyzer.API_CATEGORIES.items():
                    if any(api.lower().startswith(kw.lower()) for kw in api_list):
                        categorized[category].append(f"{dll}!{api}")
                        break
        
        return dict(categorized)
    
    @staticmethod
    def detect_suspicious_imports(imports: Dict[str, List[str]]) -> Dict[str, any]:
        """Detect suspicious API import patterns"""
        suspicious = {
            "injection_capable": False,
            "hooking_capable": False,
            "apis": []
        }
        
        injection_apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        hooking_apis = ["SetWindowsHookEx", "GetProcAddress"]
        
        all_apis = []
        for apis in imports.values():
            all_apis.extend(apis)
        
        injection_count = sum(1 for api in injection_apis if any(api in a for a in all_apis))
        hooking_count = sum(1 for api in hooking_apis if any(api in a for a in all_apis))
        
        if injection_count >= 2:
            suspicious["injection_capable"] = True
        if hooking_count >= 1:
            suspicious["hooking_capable"] = True
        
        suspicious["apis"] = all_apis
        
        return suspicious
    
    @staticmethod
    def analyze_dll_dependencies(imports: Dict[str, List[str]]) -> Dict[str, any]:
        """Analyze DLL dependencies and their purpose"""
        analysis = {
            "dll_count": len(imports),
            "system_dlls": [],
            "suspicious_dlls": [],
            "custom_dlls": [],
            "purpose": {}
        }
        
        system_dlls = {"kernel32", "ntdll", "user32", "gdi32", "advapi32", "shell32"}
        suspicious_patterns = {"ws2_32", "wininet", "urlmon"}
        
        for dll in imports.keys():
            dll_name = dll.lower().split('.')[0]
            
            if dll_name in system_dlls:
                analysis["system_dlls"].append(dll)
            elif any(pattern in dll_name for pattern in suspicious_patterns):
                analysis["suspicious_dlls"].append(dll)
            else:
                analysis["custom_dlls"].append(dll)
        
        return analysis


class MalwareBehaviorAnalyzer:
    """Analyze import patterns for malware behavior indicators"""

    BEHAVIORS = {
        "worm": ["SendMessageA", "WM_QUIT", "CloseHandle", "GetWindowsDirectory"],
        "ransomware": ["CryptEncrypt", "GetLogicalDrives", "FindFirstFileA", "DeleteFileA"],
        "spyware": ["GetClipboardData", "GetKeyboardState", "mouse_event"],
        "rootkit": ["NtSetInformationFile", "NtQuerySystemInformation"],
        "trojan": ["WinExec", "ShellExecute", "LoadLibrary"],
    }
    
    @staticmethod
    def analyze_behavior(imports: Dict[str, List[str]]) -> Dict[str, any]:
        """Determine likely malware behavior based on imports"""
        all_apis = []
        for apis in imports.values():
            all_apis.extend([api.lower() for api in apis])
        
        behaviors = {}
        for behavior_type, indicators in MalwareBehaviorAnalyzer.BEHAVIORS.items():
            matches = sum(1 for ind in indicators if any(ind.lower() in api for api in all_apis))
            if matches > 0:
                behaviors[behavior_type] = {
                    "score": matches / len(indicators),
                    "matches": matches
                }
        
        return behaviors


class ImportAnalyzerSuite:
    """Main import analysis suite"""
    
    def __init__(self, pe_path: str):
        self.pe_path = pe_path
        self.pe = None
    
    def load_pe(self) -> bool:
        """Load and parse PE file"""
        try:
            self.pe = pefile.PE(self.pe_path)
            return True
        except Exception as e:
            logger.error(f"Failed to parse PE: {e}")
            return False
    
    def run_analysis(self) -> Dict:
        """Run complete import analysis"""
        if not self.load_pe():
            return {"error": "Failed to parse PE"}

        imports = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode('utf-8', errors='ignore')
                apis = [func.name.decode('utf-8', errors='ignore') if func.name else f"Ordinal_{func.ordinal}" 
                        for func in dll.imports]
                imports[dll_name] = apis
        
        report = {
            "file": self.pe_path,
            "imports": imports,
            "categorized": ImportAnalyzer.categorize_imports(imports),
            "suspicious": ImportAnalyzer.detect_suspicious_imports(imports),
            "dll_analysis": ImportAnalyzer.analyze_dll_dependencies(imports),
            "hook_chains": APIHookDetector.detect_hook_chains(imports),
            "behavior_analysis": MalwareBehaviorAnalyzer.analyze_behavior(imports),
            "hook_detection": APIHookDetector.detect_hooks_in_section(self.pe)
        }
        
        return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Advanced API Hook Detector & Import Analyzer")
    parser.add_argument('exe', help='Path to EXE/DLL')
    parser.add_argument('-o', '--out', help='Output JSON file')
    args = parser.parse_args()
    
    analyzer = ImportAnalyzerSuite(args.exe)
    report = analyzer.run_analysis()
    
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(report, f, indent=2)
    else:
        print(json.dumps(report, indent=2, default=str))


if __name__ == '__main__':
    main()
