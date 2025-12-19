#!/usr/bin/env python3
"""
Advanced EXE Decompiler & Extractor Suite
Comprehensive PE binary analysis, resource extraction, and embedded file recovery
"""
import argparse
import os
import sys
import json
import hashlib
import struct
import io
import pefile
import capstone
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

SIGNATURES = {
    b"PK\x03\x04": {"ext": ".zip", "name": "ZIP Archive"},
    b"MZ": {"ext": ".exe", "name": "PE Executable/DLL"},
    b"7z\xBC\xAF\x27\x1C": {"ext": ".7z", "name": "7-Zip Archive"},
    b"Rar!\x1A\x07": {"ext": ".rar", "name": "RAR Archive"},
    b"Rar!\x1A\x07\x00": {"ext": ".rar", "name": "RAR Archive v5"},
    b"\x1F\x8B\x08": {"ext": ".gz", "name": "GZIP Archive"},
    b"BM": {"ext": ".bmp", "name": "BMP Image"},
    b"\x89PNG": {"ext": ".png", "name": "PNG Image"},
    b"\xFF\xD8\xFF": {"ext": ".jpg", "name": "JPEG Image"},
    b"GIF8": {"ext": ".gif", "name": "GIF Image"},
    b"II\x2A\x00": {"ext": ".tiff", "name": "TIFF Image"},
    b"RIFF": {"ext": ".wav", "name": "WAV Audio"},
    b"ID3": {"ext": ".mp3", "name": "MP3 Audio"},
    b"%PDF": {"ext": ".pdf", "name": "PDF Document"},
    b"PK\x05\x06": {"ext": ".zip", "name": "ZIP End of Central Dir"},
    b"\x7FELF": {"ext": ".elf", "name": "ELF Binary"},
    b"CAFEBABE": {"ext": ".class", "name": "Java Class"},
    b"\xCA\xFE\xBA\xBE": {"ext": ".class", "name": "Java Class"},
}

class SecurityAnalyzer:
    """Analyze security characteristics of binaries"""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        entropy = 0.0
        for i in range(256):
            freq = data.count(bytes([i]))
            if freq == 0:
                continue
            p = freq / len(data)
            entropy -= p * (len(bin(i)) - 2)
        return entropy
    
    @staticmethod
    def detect_packing(pe: pefile.PE) -> Dict[str, any]:
        """Detect common packing techniques"""
        findings = {
            "packed": False,
            "suspicious_sections": [],
            "entropy_levels": {}
        }
        
        if not hasattr(pe, 'sections'):
            return findings
        
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sec_data = pe.get_data(section.VirtualAddress, section.SizeOfRawData)
            entropy = SecurityAnalyzer.calculate_entropy(sec_data)
            findings["entropy_levels"][sec_name] = entropy

            if entropy > 7.0:
                findings["packed"] = True
                findings["suspicious_sections"].append(sec_name)
        
        return findings
    
    @staticmethod
    def extract_imports(pe: pefile.PE) -> Dict[str, List[str]]:
        """Extract all imported functions"""
        imports = defaultdict(list)
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports
        
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = dll.dll.decode('utf-8', errors='ignore')
            for func in dll.imports:
                func_name = func.name.decode('utf-8', errors='ignore') if func.name else f"Ordinal_{func.ordinal}"
                imports[dll_name].append(func_name)
        
        return imports
    
    @staticmethod
    def extract_exports(pe: pefile.PE) -> List[str]:
        """Extract all exported functions"""
        exports = []
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports
        
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exp_name = exp.name.decode('utf-8', errors='ignore')
            exports.append(exp_name)
        
        return exports


class AssemblyAnalyzer:
    """Analyze x86/x64 assembly code"""
    
    @staticmethod
    def disassemble_section(pe: pefile.PE, section_name: str = ".text") -> List[str]:
        """Disassemble a PE section"""
        results = []

        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_32
        if pe.FILE_HEADER.Machine == 0x8664:
            mode = capstone.CS_MODE_64
        
        md = capstone.Cs(arch, mode)
        md.detail = True

        for section in pe.sections:
            if section.Name.decode('utf-8', errors='ignore').strip('\x00') == section_name:
                code = pe.get_data(section.VirtualAddress, section.SizeOfRawData)
                for instr in md.disasm(code, section.VirtualAddress):
                    results.append(f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
        
        return results


class DotNetAnalyzer:
    """Analyze .NET assemblies"""
    
    @staticmethod
    def is_dotnet(pe: pefile.PE) -> bool:
        """Check if PE is a .NET assembly"""
        return hasattr(pe, 'DIRECTORY_ENTRY_COM20_HEADER')
    
    @staticmethod
    def extract_dotnet_metadata(pe: pefile.PE) -> Dict[str, any]:
        """Extract .NET metadata"""
        metadata = {
            "is_dotnet": DotNetAnalyzer.is_dotnet(pe),
            "runtime_version": None,
            "entry_point": None
        }
        
        if not metadata["is_dotnet"]:
            return metadata
        
        try:
            com_hdr = pe.DIRECTORY_ENTRY_COM20_HEADER
            metadata["entry_point"] = com_hdr.EntryPointToken
            if hasattr(com_hdr, 'MajorRuntimeVersion'):
                metadata["runtime_version"] = f"{com_hdr.MajorRuntimeVersion}.{com_hdr.MinorRuntimeVersion}"
        except:
            pass
        
        return metadata


class CarvingEngine:
    """Advanced file carving engine with heuristics"""
    
    def __init__(self, data: bytes):
        self.data = data
        self.carvings = []
    
    def find_signatures(self) -> List[Tuple[int, bytes, str]]:
        """Find all file signatures with offsets"""
        findings = []
        for sig, meta in SIGNATURES.items():
            offsets = self._find_all_offsets(sig)
            for off in offsets:
                findings.append((off, sig, meta['ext']))
        return sorted(findings, key=lambda x: x[0])
    
    def _find_all_offsets(self, sig: bytes) -> List[int]:
        """Find all occurrences of a signature"""
        offsets = []
        start = 0
        while True:
            idx = self.data.find(sig, start)
            if idx == -1:
                break
            offsets.append(idx)
            start = idx + 1
        return offsets
    
    def carve_files(self, out_dir: str, min_size: int = 64, max_size: int = None) -> List[str]:
        """Carve embedded files based on signatures"""
        os.makedirs(out_dir, exist_ok=True)
        findings = self.find_signatures()
        results = []
        
        for i, (off, sig, ext) in enumerate(findings):
            start = off
            end = len(self.data)
            
            if i + 1 < len(findings):
                end = findings[i + 1][0]
            
            if max_size:
                end = min(end, start + max_size)
            
            size = end - start
            if size < min_size:
                continue
            
            out_path = os.path.join(out_dir, f"carved_{start:08x}{ext}")
            try:
                with open(out_path, 'wb') as f:
                    f.write(self.data[start:end])
                results.append(out_path)
                logger.info(f"Carved: {out_path} (offset: 0x{start:x}, size: {size} bytes)")
            except Exception as e:
                logger.error(f"Failed to carve at {start}: {e}")
        
        return results


class ResourceExtractor:
    """Advanced PE resource extraction"""
    
    @staticmethod
    def extract_all_resources(pe_path: str, out_dir: str) -> Dict[str, any]:
        """Extract all PE resources with metadata"""
        os.makedirs(out_dir, exist_ok=True)
        results = {
            "total": 0,
            "by_type": defaultdict(list),
            "failed": []
        }
        
        try:
            pe = pefile.PE(pe_path)
        except Exception as e:
            logger.error(f"Failed to parse PE: {e}")
            return results
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            logger.warning("No resources directory found")
            return results
        
        counter = 0
        try:
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if not hasattr(entry, 'directory'):
                    continue
                for res in entry.directory.entries:
                    if not hasattr(res, 'directory'):
                        continue
                    for res_lang in res.directory.entries:
                        try:
                            data_rva = res_lang.data.struct.OffsetToData
                            size = res_lang.data.struct.Size
                            data = pe.get_data(data_rva, size)
                            
                            res_type = str(entry.struct.Id)
                            out_path = os.path.join(out_dir, f"res_{counter:04d}_{res_type}")
                            
                            with open(out_path, 'wb') as f:
                                f.write(data)
                            
                            results["by_type"][res_type].append(out_path)
                            results["total"] += 1
                            counter += 1
                            logger.info(f"Extracted resource: {out_path}")
                        except Exception as e:
                            results["failed"].append(str(e))
        except Exception as e:
            logger.error(f"Error during resource extraction: {e}")
        
        return results


class ConfigExtractor:
    """Heuristic configuration string extraction"""
    
    @staticmethod
    def extract_strings(data: bytes, min_len: int = 4, encoding: str = 'ascii') -> List[str]:
        """Extract printable strings from binary"""
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_len:
            strings.append(''.join(current))
        
        return strings
    
    @staticmethod
    def extract_unicode_strings(data: bytes, min_len: int = 4) -> List[str]:
        """Extract Unicode strings from binary"""
        strings = []
        current = []
        
        i = 0
        while i < len(data) - 1:
            b1, b2 = data[i], data[i + 1]
            
            if b2 == 0 and 32 <= b1 < 127:
                current.append(chr(b1))
                i += 2
            else:
                if len(current) >= min_len:
                    strings.append(''.join(current))
                current = []
                i += 1
        
        return strings
    
    @staticmethod
    def extract_urls_and_ips(strings: List[str]) -> Dict[str, List[str]]:
        """Extract URLs and IPs from strings"""
        import re
        urls = []
        ips = []
        
        for s in strings:
            if re.match(r'^https?://', s):
                urls.append(s)
            if re.match(r'^\d+\.\d+\.\d+\.\d+', s):
                ips.append(s)
        
        return {"urls": urls, "ips": ips}


class DebugInfoExtractor:
    """Extract debug and symbol information"""
    
    @staticmethod
    def extract_debug_info(pe: pefile.PE) -> Dict[str, any]:
        """Extract debug directory information"""
        debug_info = {
            "has_debug": False,
            "entries": []
        }
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            return debug_info
        
        debug_info["has_debug"] = True
        
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            debug_entry = {
                "type": entry.struct.Type,
                "size": entry.struct.SizeOfData,
                "rva": entry.struct.AddressOfRawData
            }
            debug_info["entries"].append(debug_entry)
        
        return debug_info


class DecompilerSuite:
    """Main decompilation and analysis suite"""
    
    def __init__(self, exe_path: str, out_dir: str = "decompiled_output"):
        self.exe_path = exe_path
        self.out_dir = out_dir
        self.report = {}
        os.makedirs(out_dir, exist_ok=True)
    
    def run_full_analysis(self, options: Dict[str, bool]) -> Dict[str, any]:
        """Run comprehensive analysis"""
        logger.info(f"Starting analysis of {self.exe_path}")
        
        with open(self.exe_path, 'rb') as f:
            binary_data = f.read()

        try:
            pe = pefile.PE(self.exe_path)
        except Exception as e:
            logger.error(f"Failed to parse PE: {e}")
            return {"error": str(e)}

        self.report["basic_info"] = {
            "filename": os.path.basename(self.exe_path),
            "size": len(binary_data),
            "md5": hashlib.md5(binary_data).hexdigest(),
            "sha256": hashlib.sha256(binary_data).hexdigest(),
            "machine": hex(pe.FILE_HEADER.Machine),
            "sections": len(pe.sections),
            "is_dotnet": DotNetAnalyzer.is_dotnet(pe)
        }

        if options.get("security", True):
            self.report["security"] = SecurityAnalyzer.detect_packing(pe)
            self.report["imports"] = SecurityAnalyzer.extract_imports(pe)
            self.report["exports"] = SecurityAnalyzer.extract_exports(pe)

        if options.get("dotnet", True):
            self.report["dotnet"] = DotNetAnalyzer.extract_dotnet_metadata(pe)

        if options.get("debug", True):
            self.report["debug_info"] = DebugInfoExtractor.extract_debug_info(pe)

        if options.get("resources", True):
            res_dir = os.path.join(self.out_dir, "resources")
            self.report["resources"] = ResourceExtractor.extract_all_resources(self.exe_path, res_dir)
        
        if options.get("carve", True):
            carving_dir = os.path.join(self.out_dir, "carved")
            carver = CarvingEngine(binary_data)
            self.report["carved_files"] = carver.carve_files(carving_dir)

        if options.get("strings", True):
            strings = ConfigExtractor.extract_strings(binary_data)
            unicode_strings = ConfigExtractor.extract_unicode_strings(binary_data)
            intel = ConfigExtractor.extract_urls_and_ips(strings + unicode_strings)
            self.report["strings"] = {
                "ascii_count": len(strings),
                "unicode_count": len(unicode_strings),
                "intelligence": intel
            }

            with open(os.path.join(self.out_dir, "ascii_strings.txt"), 'w') as f:
                f.write('\n'.join(strings))
            with open(os.path.join(self.out_dir, "unicode_strings.txt"), 'w') as f:
                f.write('\n'.join(unicode_strings))

        with open(os.path.join(self.out_dir, "analysis_report.json"), 'w') as f:
            json.dump(self.report, f, indent=2, default=str)
        
        logger.info(f"Analysis complete. Report saved to {self.out_dir}")
        return self.report


def main():
    parser = argparse.ArgumentParser(
        description='Advanced EXE Decompiler & Extractor Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python decompiler_suite.py sample.exe
  python decompiler_suite.py sample.exe -o /output/path
  python decompiler_suite.py sample.exe --no-carve --no-dotnet
        """
    )
    
    parser.add_argument('exe', help='Path to EXE/DLL file')
    parser.add_argument('-o', '--out', default='decompiled_output', help='Output directory')
    parser.add_argument('--no-resources', action='store_true', help='Skip resource extraction')
    parser.add_argument('--no-carve', action='store_true', help='Skip file carving')
    parser.add_argument('--no-security', action='store_true', help='Skip security analysis')
    parser.add_argument('--no-strings', action='store_true', help='Skip string extraction')
    parser.add_argument('--no-dotnet', action='store_true', help='Skip .NET analysis')
    parser.add_argument('--no-debug', action='store_true', help='Skip debug info extraction')
    
    args = parser.parse_args()
    
    options = {
        "resources": not args.no_resources,
        "carve": not args.no_carve,
        "security": not args.no_security,
        "strings": not args.no_strings,
        "dotnet": not args.no_dotnet,
        "debug": not args.no_debug
    }
    
    suite = DecompilerSuite(args.exe, args.out)
    report = suite.run_full_analysis(options)
    
    print("\n=== Analysis Report ===")
    print(json.dumps(report, indent=2, default=str))


if __name__ == '__main__':
    main()
