#!/usr/bin/env python3

import struct
import logging
import json
import math
from typing import Dict, List, Any, Tuple, Set, Optional
from collections import defaultdict, Counter
import re
import pefile
from .config_extractor import ConfigExtractor

logger = logging.getLogger(__name__)


class APIHookDetector:
    """
    Advanced API Hook detection integrated from api_hook_detector.py
    Detects common API hooking techniques and suspicious patterns
    """
    
    HOOK_PATTERNS = {
        "jmp_hook": b"\xFF\x25",
        "call_hook": b"\xE8",
        "int3_hook": b"\xCC",
        "nop_hook": b"\x90\x90",
        "indirect_jmp": b"\xFF\x25",
        "trampoline": b"\x55\x48\x89\xe5",
    }
    
    SUSPICIOUS_SEQUENCES = [
        ("GetProcAddress", "WriteProcessMemory"),
        ("VirtualAllocEx", "WriteProcessMemory"),
        ("CreateRemoteThread", "WaitForSingleObject"),
        ("SetWindowsHookEx", "GetMessage"),
        ("DLL_PROCESS_ATTACH", "CreateThread"),
    ]
    
    @staticmethod
    def detect_hooks_in_section(pe: pefile.PE, section_name: str = ".text") -> Dict[str, Any]:
        """Detect hooks in a specific section"""
        findings = {
            "hooked": False,
            "patterns_found": [],
            "suspicious_regions": [],
            "risk_score": 0,
        }
        
        if not hasattr(pe, 'sections'):
            return findings
        
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            if sec_name != section_name:
                continue
            
            try:
                code = pe.get_data(section.VirtualAddress, section.SizeOfRawData)
            except:
                continue
            
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
                        "pattern": pattern.hex(),
                    })
                    findings["risk_score"] += 15
                    offset += len(pattern)
        
        return findings
    
    @staticmethod
    def _is_likely_hook(code: bytes, offset: int, pattern: bytes) -> bool:
        """Heuristic to determine if pattern is likely a hook"""
        if offset < 16:
            return False
        return True
    
    @staticmethod
    def detect_hook_chains(imports: Dict[str, List[str]]) -> List[Tuple[str, str]]:
        """Detect sequences of imports that suggest hooking"""
        chains = []
        
        all_imports = [func for dll_imports in imports.values() for func in dll_imports]
        
        for sus_pair in APIHookDetector.SUSPICIOUS_SEQUENCES:
            if sus_pair[0] in all_imports and sus_pair[1] in all_imports:
                chains.append(sus_pair)
        
        return chains


class SecurityAnalyzer:
    """
    Comprehensive security analysis for PE binaries
    Detects packing, hooks, suspicious imports, and malware signatures
    """

    MALWARE_SIGNATURES = {
        "ransomware": {
            "imports": ["CryptEncrypt", "CryptDecrypt", "SetFilePointer"],
            "strings": ["*.encrypted", "bitcoin", "wallet", "payment"],
            "behavior": "File encryption and extortion",
            "weight": 40,
        },
        "spyware": {
            "imports": ["GetWindowText", "SetWindowsHookEx", "GetClipboardData"],
            "strings": ["hwnd", "keyboard", "monitor", "screen"],
            "behavior": "Keylogging and screen capture",
            "weight": 30,
        },
        "trojan": {
            "imports": ["ShellExecute", "CreateProcess", "WinExec"],
            "strings": ["cmd.exe", "powershell.exe", "system32"],
            "behavior": "Command execution",
            "weight": 35,
        },
        "worm": {
            "imports": ["InternetOpen", "InternetConnect", "HttpSendRequest"],
            "strings": ["http://", "https://", ".exe"],
            "behavior": "Network propagation",
            "weight": 25,
        },
        "rootkit": {
            "imports": ["SetWindowsHookEx", "CreateRemoteThread", "WriteProcessMemory"],
            "strings": ["kernel32", "ntdll", "driver"],
            "behavior": "Low-level system access",
            "weight": 50,
        },
        "miner": {
            "imports": ["CryptAcquireContext", "InternetOpenUrl"],
            "strings": ["stratum", "pool", "bitcoin", "ethereum"],
            "behavior": "Cryptocurrency mining",
            "weight": 45,
        },
    }

    HOOK_PATTERNS = [
        (b"\x55\x48\x89\xe5", "Stack frame setup (x64)"),
        (b"\xff\x25", "Indirect jump (32-bit hooking)"),
        (b"\x48\xff\x25", "Indirect jump (x64 hooking)"),
        (b"\x58\xc3", "Suspicious ret pattern"),
        (b"\xe9", "Long jump (potential detour)"),
    ]

    INJECTION_IMPORTS = [
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "SetThreadContext",
        "ResumeThread",
        "CreateProcessA",
        "CreateProcessW",
        "OpenProcess",
    ]
    
    def __init__(self, pe_object=None):
        """Initialize security analyzer"""
        self.pe = pe_object
        self.findings = {}
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy correctly"""
        if not data:
            return 0.0
        
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in freq:
            if count == 0:
                continue
            p = count / data_len
            entropy -= p * math.log2(p)
        
        return entropy
    
    def detect_packing(self) -> Dict[str, Any]:
        """Detect if binary is packed"""
        packing = {
            "is_packed": False,
            "indicators": [],
            "entropy": 0.0,
        }
        
        if not self.pe:
            return packing
        
        try:
            total_entropy = 0.0
            section_count = len(self.pe.sections)
            for section in self.pe.sections:
                data = self.pe.get_data(section.VirtualAddress, section.SizeOfRawData)
                entropy = self.calculate_entropy(data)
                total_entropy += entropy
                if entropy > 6.5:
                    packing["indicators"].append(f"High entropy in {section.Name.decode().rstrip('\x00')}: {entropy}")
            
            avg_entropy = total_entropy / max(1, section_count)
            packing["entropy"] = avg_entropy
            if avg_entropy > 6.0:
                packing["is_packed"] = True
                packing["indicators"].append("High average entropy")
            
            if section_count < 3:
                packing["indicators"].append("Few sections")
            
            packing["is_packed"] = len(packing["indicators"]) > 1
        except Exception as e:
            logger.debug(f"Packing detection error: {e}")
        
        return packing
    
    def detect_injection_imports(self) -> Dict[str, Any]:
        """Detect code injection capabilities"""
        injection = {
            "capable": False,
            "matched_imports": [],
            "risk_level": "low",
        }
        
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return injection
        
        matched = []
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            for func in dll.imports:
                func_name = func.name.decode('utf-8', errors='ignore') if func.name else ""
                if func_name in self.INJECTION_IMPORTS:
                    matched.append(func_name)
        
        injection["matched_imports"] = matched
        injection["capable"] = len(matched) > 2
        if len(matched) > 4:
            injection["risk_level"] = "high"
        elif len(matched) > 2:
            injection["risk_level"] = "medium"
        
        return injection
    
    def analyze_hooks(self) -> Dict[str, Any]:
        """Analyze for API hooks"""
        hooks = {
            "detected": False,
            "patterns": [],
            "chains": [],
        }
        
        if not self.pe:
            return hooks
        
        text_hooks = APIHookDetector.detect_hooks_in_section(self.pe, ".text")
        hooks["patterns"] = text_hooks["patterns_found"]
        
        imports = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode('utf-8', errors='ignore').rstrip('\x00')
                imports[dll_name] = [func.name.decode('utf-8', errors='ignore').rstrip('\x00') if func.name else "" for func in dll.imports]
        
        hooks["chains"] = APIHookDetector.detect_hook_chains(imports)
        
        hooks["detected"] = len(hooks["patterns"]) > 0 or len(hooks["chains"]) > 0
        
        return hooks
    
    def extract_suspicious_strings(self) -> Dict[str, Any]:
        """Extract suspicious configuration strings"""
        suspicious = {
            "urls": [],
            "emails": [],
            "registry_keys": [],
            "file_paths": [],
            "command_patterns": [],
        }
        
        if not self.pe:
            return suspicious
        
        try:
            for section in self.pe.sections:
                try:
                    data = self.pe.get_data(section.VirtualAddress, section.SizeOfRawData)
                    text = data.decode('utf-8', errors='ignore')

                    suspicious["urls"].extend(re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text))
                    suspicious["emails"].extend(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text))
                    suspicious["registry_keys"].extend(re.findall(r'HKEY_[A-Z_]+\\[^\x00]+', text))
                    suspicious["file_paths"].extend(re.findall(r'(?:[A-Z]:\\|/)[\w\\\-_.]+\.\w{2,4}', text))
                    suspicious["command_patterns"].extend(re.findall(r'(cmd|powershell)\.exe /c .+', text, re.IGNORECASE))
                except:
                    pass
        except Exception as e:
            logger.debug(f"String extraction error: {e}")
        
        return suspicious
    
    def analyze_imports_risk(self) -> Dict[str, Any]:
        risk_analysis = {
            "total_imports": 0,
            "dangerous_imports": [],
            "suspicious_patterns": [],
            "overall_risk": "low",
            "risk_score": 0,
        }
        
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return risk_analysis
        
        dangerous_apis = {
            "WriteProcessMemory": {"desc": "Can write to other processes", "weight": 20},
            "CreateRemoteThread": {"desc": "Can execute code in other processes", "weight": 25},
            "VirtualAllocEx": {"desc": "Can allocate memory in other processes", "weight": 15},
            "SetWindowsHookEx": {"desc": "Can inject DLLs via hooks", "weight": 20},
            "GetWindowText": {"desc": "Can capture window content", "weight": 10},
            "GetClipboardData": {"desc": "Can read clipboard", "weight": 10},
            "InternetOpen": {"desc": "Network access", "weight": 5},
            "CryptEncrypt": {"desc": "Encryption capability", "weight": 15},
            "CryptDecrypt": {"desc": "Decryption capability", "weight": 15},
            "ShellExecute": {"desc": "Execute external programs", "weight": 10},
            "WinExec": {"desc": "Execute programs (legacy)", "weight": 10},
        }
        
        total = 0
        score = 0
        
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            for func in dll.imports:
                total += 1
                func_name = func.name.decode('utf-8', errors='ignore') if func.name else ""
                if func_name in dangerous_apis:
                    api_info = dangerous_apis[func_name]
                    risk_analysis["dangerous_imports"].append({
                        "api": func_name,
                        "risk": api_info["desc"]
                    })
                    score += api_info["weight"]
        
        risk_analysis["total_imports"] = total
        risk_analysis["risk_score"] = min(100, score)
        
        if risk_analysis["risk_score"] > 75:
            risk_analysis["overall_risk"] = "critical"
        elif risk_analysis["risk_score"] > 50:
            risk_analysis["overall_risk"] = "high"
        elif risk_analysis["risk_score"] > 25:
            risk_analysis["overall_risk"] = "medium"
        
        return risk_analysis
    
    def classify_malware_behavior(self, imports: Dict, strings: List[str] = None) -> List[Dict[str, Any]]:
        """Classify potential malware behavior"""
        detections = []
        
        all_imports = [func for dll_imports in imports.values() for func in dll_imports]
        
        for malware_type, signature in self.MALWARE_SIGNATURES.items():
            confidence = 0
            matched_features = []

            for required_import in signature["imports"]:
                if required_import in all_imports:
                    confidence += signature["weight"] / len(signature["imports"])
                    matched_features.append(f"Import: {required_import}")

            if strings:
                for pattern in signature["strings"]:
                    pattern_regex = pattern.replace("*", ".*")
                    if any(re.search(pattern_regex, s, re.IGNORECASE) for s in strings):
                        confidence += 20
                        matched_features.append(f"String: {pattern}")
            
            if confidence > 30:
                detections.append({
                    "type": malware_type,
                    "confidence": min(100, confidence),
                    "behavior": signature["behavior"],
                    "matched_features": matched_features,
                })
        
        return detections
    
    def get_full_security_report(self, binary_data: Optional[bytes] = None) -> Dict[str, Any]:
        """Generate comprehensive security report with config extraction"""
        report = {
            "packing_analysis": self.detect_packing(),
            "injection_analysis": self.detect_injection_imports(),
            "hooks_analysis": self.analyze_hooks(),
            "import_risk": self.analyze_imports_risk(),
            "suspicious_strings": self.extract_suspicious_strings(),
            "timestamp": __import__('datetime').datetime.now().isoformat(),
        }

        imports = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode('utf-8', errors='ignore').rstrip('\x00')
                imports[dll_name] = [func.name.decode('utf-8', errors='ignore').rstrip('\x00') if func.name else "" for func in dll.imports]
        
        strings = []
        report["malware_classification"] = self.classify_malware_behavior(imports, strings)

        if binary_data:
            try:
                config_extractor = ConfigExtractor()
                config_extractor.extract_from_binary(binary_data)
                report["configuration_extraction"] = config_extractor.get_report()
            except Exception as e:
                logger.warning(f"Config extraction failed: {e}")
                report["configuration_extraction"] = {"error": str(e)}
        
        return report


if __name__ == "__main__":
    analyzer = SecurityAnalyzer()
    report = analyzer.get_full_security_report()
    print(json.dumps(report, indent=2, default=str))
