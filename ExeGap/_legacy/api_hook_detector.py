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
                        "offset": hex(section.VirtualAddress + offset),
                        "pattern": pattern.hex()
                    })
                    offset += len(pattern)
        
        return findings
    
    @staticmethod
    def _is_likely_hook(code: bytes, offset: int, pattern: bytes) -> bool:
        """Heuristic to determine if pattern is likely a hook"""
        if offset < 5 or offset > len(code) - 10:
            return False
        return True
    
    @staticmethod
    def detect_hook_chains(imports: Dict[str, List[str]]) -> List[Tuple[str, str]]:
        """Detect sequences of imports that suggest hooking"""
        chains = []
        
        all_imports = [func for dll_imports in imports.values() for func in dll_imports]
        
        for sus_pair in APIHookDetector.SUSPICIOUS_SEQUENCES:
            if all(func in all_imports for func in sus_pair):
                chains.append(sus_pair)
        
        return chains


class ImportAnalyzer:
    """Analyze PE imports"""

    DANGEROUS_APIS = {
        "kernel32.dll": [
            "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx",
            "SetWindowsHookEx", "GetProcAddress", "LoadLibraryA",
            "CreateProcessA", "OpenProcess", "ResumeThread"
        ],
        "user32.dll": ["SetWindowsHookEx", "GetWindowText", "GetClipboardData"],
        "advapi32.dll": ["CryptEncrypt", "CryptDecrypt", "RegSetValueEx"],
        "ntdll.dll": ["NtWriteVirtualMemory", "NtCreateThreadEx"],
        "wininet.dll": ["InternetOpen", "InternetConnect", "HttpSendRequest"],
        "shell32.dll": ["ShellExecute", "ShellExecuteEx"],
    }
    
    CATEGORIES = {
        "process_injection": ["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"],
        "hooking": ["SetWindowsHookEx", "GetProcAddress"],
        "network": ["InternetOpen", "InternetConnect", "HttpSendRequest"],
        "encryption": ["CryptEncrypt", "CryptDecrypt"],
        "execution": ["ShellExecute", "CreateProcessA", "WinExec"],
    }
    
    @staticmethod
    def categorize_imports(imports: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Categorize imports by function type"""
        categories = defaultdict(list)
        
        for dll, funcs in imports.items():
            for func in funcs:
                for cat, apis in ImportAnalyzer.CATEGORIES.items():
                    if func in apis:
                        categories[cat].append(f"{dll}!{func}")
        
        return dict(categories)
    
    @staticmethod
    def detect_suspicious_imports(imports: Dict[str, List[str]]) -> List[str]:
        """Detect potentially malicious imports"""
        suspicious = []
        
        for dll, funcs in imports.items():
            dll_lower = dll.lower()
            if dll_lower in ImportAnalyzer.DANGEROUS_APIS:
                for func in funcs:
                    if func in ImportAnalyzer.DANGEROUS_APIS[dll_lower]:
                        suspicious.append(f"{dll}!{func}")
        
        return suspicious
    
    @staticmethod
    def analyze_dll_dependencies(imports: Dict[str, List[str]]) -> Dict[str, int]:
        """Analyze DLL usage"""
        dll_stats = {}
        
        for dll in imports:
            dll_stats[dll] = len(imports[dll])
        
        return dll_stats


class MalwareBehaviorAnalyzer:
    """Analyze imports for malware behaviors"""

    MALWARE_SIGNATURES = {
        "ransomware": ["CryptEncrypt", "CryptDecrypt", "SetFilePointer"],
        "spyware": ["GetWindowText", "SetWindowsHookEx", "GetClipboardData"],
        "trojan": ["ShellExecute", "CreateProcessA", "WinExec"],
        "worm": ["InternetOpen", "InternetConnect", "HttpSendRequest"],
        "rootkit": ["SetWindowsHookEx", "CreateRemoteThread", "WriteProcessMemory"],
    }
    
    @staticmethod
    def analyze_behavior(imports: Dict[str, List[str]]) -> Dict[str, Dict]:
        """Detect potential malware behaviors"""
        behaviors = {}
        
        all_imports = [func for dll_imports in imports.values() for func in dll_imports]
        
        for malware_type, indicators in MalwareBehaviorAnalyzer.MALWARE_SIGNATURES.items():
            matches = [ind for ind in indicators if ind in all_imports]
            if matches:
                behaviors[malware_type] = {
                    "confidence": len(matches) / len(indicators),
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
