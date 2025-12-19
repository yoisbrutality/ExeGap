#!/usr/bin/env python3
"""
Advanced Security Analysis Module
Detects malware signatures, packing, API hooks, and suspicious behavior patterns
Integrates api_hook_detector.py and config extraction capabilities
"""
import struct
import logging
import json
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
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
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
        
        for dll_imports in imports.values():
            for i, func1 in enumerate(dll_imports):
                for func2 in dll_imports[i+1:]:
                    for sus_pair in APIHookDetector.SUSPICIOUS_SEQUENCES:
                        if (func1 == sus_pair[0] and func2 == sus_pair[1]):
                            chains.append((func1, func2))
        
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
        },
        "spyware": {
            "imports": ["GetWindowText", "SetWindowsHookEx", "GetClipboardData"],
            "strings": ["hwnd", "keyboard", "monitor", "screen"],
            "behavior": "Keylogging and screen capture",
        },
        "trojan": {
            "imports": ["ShellExecute", "CreateProcess", "WinExec"],
            "strings": ["cmd.exe", "powershell.exe", "system32"],
            "behavior": "Command execution",
        },
        "worm": {
            "imports": ["InternetOpen", "InternetConnect", "HttpSendRequest"],
            "strings": ["http://", "https://", ".exe"],
            "behavior": "Network propagation",
        },
        "rootkit": {
            "imports": ["SetWindowsHookEx", "CreateRemoteThread", "WriteProcessMemory"],
            "strings": ["kernel32", "ntdll", "driver"],
            "behavior": "Low-level system access",
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
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        frequency = Counter(data)
        
        for count in frequency.values():
            probability = count / len(data)
            entropy -= probability * (len(bin(probability)) - 2)
        
        return round(entropy, 3)
    
    def detect_packing(self) -> Dict[str, Any]:
        """Detect common packing techniques"""
        findings = {
            "packed": False,
            "suspicious_sections": [],
            "entropy_analysis": {},
            "known_packers": [],
            "risk_level": "low",
        }
        
        if not self.pe or not hasattr(self.pe, 'sections'):
            return findings
        
        high_entropy_count = 0
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            section_data = self.pe.get_data(section.VirtualAddress, section.SizeOfRawData)
            entropy = self.calculate_entropy(section_data)
            
            findings["entropy_analysis"][section_name] = entropy

            if entropy > 7.5:
                high_entropy_count += 1
                findings["suspicious_sections"].append({
                    "name": section_name,
                    "entropy": entropy,
                    "reason": "High entropy indicates compression or encryption"
                })

            packer = self._identify_packer(section_name, entropy)
            if packer:
                findings["known_packers"].append(packer)
        
        if high_entropy_count > 2 or findings["known_packers"]:
            findings["packed"] = True
            findings["risk_level"] = "high"
        elif high_entropy_count > 0:
            findings["risk_level"] = "medium"
        
        return findings
    
    def _identify_packer(self, section_name: str, entropy: float) -> Optional[str]:
        """Identify known packers by section name"""
        packer_signatures = {
            ".UPX": "UPX",
            ".packed": "Generic Packer",
            ".rsrc": "Resource Section",
            ".reloc": "Relocation",
            ".text": "Code Section",
            ".data": "Data Section",
            "ASLR": "ASLR Protection",
            ".enigma": "Enigma Protector",
            ".aspack": "ASPack",
            ".therawcode": "The Ghostware",
        }
        
        for sig, packer_name in packer_signatures.items():
            if sig.lower() in section_name.lower():
                return {"name": packer_name, "entropy": entropy}
        
        return None
    
    def detect_injection_imports(self) -> Dict[str, List[str]]:
        """Detect process injection capabilities"""
        findings = {
            "has_injection_capability": False,
            "injection_imports": [],
            "risk_score": 0,
        }
        
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return findings
        
        found_imports = []
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            for func in dll.imports:
                func_name = func.name.decode('utf-8', errors='ignore') if func.name else ""
                if func_name in self.INJECTION_IMPORTS:
                    found_imports.append(func_name)
        
        findings["injection_imports"] = found_imports
        findings["has_injection_capability"] = len(found_imports) > 3
        findings["risk_score"] = min(100, len(found_imports) * 15)
        
        return findings
    
    def detect_api_hooks(self) -> Dict[str, Any]:
        """Detect API hooks using integrated detector"""
        if not self.pe:
            return {"hooks_detected": False}
        
        hooks = APIHookDetector.detect_hooks_in_section(self.pe, ".text")
        
        if self.pe and hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = {}
            for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode('utf-8', errors='ignore')
                imports[dll_name] = []
                for func in dll.imports:
                    func_name = func.name.decode('utf-8', errors='ignore') if func.name else f"Ordinal_{func.ordinal}"
                    imports[dll_name].append(func_name)
            
            hook_chains = APIHookDetector.detect_hook_chains(imports)
            hooks["suspicious_chains"] = hook_chains
        
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

                    urls = re.findall(r'https?://[^\x00\s<>"{}|\\^`\[\]]+', data.decode('utf-8', errors='ignore'))
                    suspicious["urls"].extend(urls)

                    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data.decode('utf-8', errors='ignore'))
                    suspicious["emails"].extend(emails)

                    registry = re.findall(r'HKEY_[A-Z_]+', data.decode('utf-8', errors='ignore'))
                    suspicious["registry_keys"].extend(registry)
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
            "WriteProcessMemory": "Can write to other processes",
            "CreateRemoteThread": "Can execute code in other processes",
            "VirtualAllocEx": "Can allocate memory in other processes",
            "SetWindowsHookEx": "Can inject DLLs via hooks",
            "GetWindowText": "Can capture window content",
            "GetClipboardData": "Can read clipboard",
            "InternetOpen": "Network access",
            "CryptEncrypt": "Encryption capability",
            "CryptDecrypt": "Decryption capability",
            "ShellExecute": "Execute external programs",
            "WinExec": "Execute programs (legacy)",
        }
        
        total = 0
        risky_count = 0
        
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            for func in dll.imports:
                total += 1
                func_name = func.name.decode('utf-8', errors='ignore') if func.name else ""
                if func_name in dangerous_apis:
                    risky_count += 1
                    risk_analysis["dangerous_imports"].append({
                        "api": func_name,
                        "risk": dangerous_apis[func_name]
                    })
        
        risk_analysis["total_imports"] = total
        risk_analysis["risk_score"] = min(100, (risky_count / max(1, total)) * 100)
        
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
        
        for malware_type, signature in self.MALWARE_SIGNATURES.items():
            confidence = 0
            matched_features = []

            for required_import in signature["imports"]:
                for dll_imports in imports.values():
                    if required_import in dll_imports:
                        confidence += 30
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
            "import_risk": self.analyze_imports_risk(),
            "timestamp": __import__('datetime').datetime.now().isoformat(),
        }

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
