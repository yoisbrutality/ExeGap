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
import math

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
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
    
    @staticmethod
    def detect_packing(pe: pefile.PE) -> Dict[str, any]:
        """Detect common packing techniques"""
        packing = {
            "packed": False,
            "suspicious_sections": [],
            "entropy_threshold": 6.5
        }
        
        for section in pe.sections:
            data = pe.get_data(section.VirtualAddress, section.SizeOfRawData)
            entropy = SecurityAnalyzer.calculate_entropy(data)
            if entropy > packing["entropy_threshold"]:
                packing["packed"] = True
                packing["suspicious_sections"].append({
                    "name": section.Name.decode().rstrip('\x00'),
                    "entropy": entropy
                })
        
        return packing


class CarvingEngine:
    """Engine for carving embedded files"""
    
    def __init__(self, data: bytes, out_dir: str):
        self.data = data
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
    
    def carve_all(self):
        """Carve all embedded files"""
        found = []
        for sig, info in SIGNATURES.items():
            offset = 0
            while True:
                offset = self.data.find(sig, offset)
                if offset == -1:
                    break
                self._carve_file(offset, info["ext"], info["name"])
                offset += 1
        return found
    
    def _carve_file(self, offset: int, ext: str, name: str):
        """Carve single file"""
        size = len(self.data) - offset
        out_name = f"carved_{offset:08x}{ext}"
        out_path = os.path.join(self.out_dir, out_name)
        
        with open(out_path, 'wb') as f:
            f.write(self.data[offset:offset + size])
        
        logger.info(f"Carved {name} at {hex(offset)}")


class ResourceExtractor:
    """Extract PE resources"""
    
    @staticmethod
    def extract_resources(pe_path: str, out_dir: str):
        pe = pefile.PE(pe_path)
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return {"total": 0}
        
        count = 0
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(entry, 'directory'):
                for res in entry.directory.entries:
                    if hasattr(res, 'directory'):
                        for res_lang in res.directory.entries:
                            data_rva = res_lang.data.struct.OffsetToData
                            size = res_lang.data.struct.Size
                            data = pe.get_data(data_rva, size)
                            out_path = os.path.join(out_dir, f"resource_{count}.bin")
                            with open(out_path, 'wb') as f:
                                f.write(data)
                            count += 1
        return {"total": count}


class ConfigExtractor:
    """Extract strings and configs"""
    
    @staticmethod
    def extract_strings(data: bytes) -> Dict:
        """Extract ASCII and Unicode strings"""
        ascii_strings = []
        unicode_strings = []

        current = ''
        for byte in data:
            if 32 <= byte <= 126:
                current += chr(byte)
            else:
                if len(current) >= 4:
                    ascii_strings.append(current)
                current = ''

        current = ''
        i = 0
        while i < len(data) - 1:
            if data[i+1] == 0 and 32 <= data[i] <= 126:
                current += chr(data[i])
            else:
                if len(current) >= 4:
                    unicode_strings.append(current)
                current = ''
            i += 2
        
        return {
            "ascii": ascii_strings,
            "unicode": unicode_strings,
            "ascii_count": len(ascii_strings),
            "unicode_count": len(unicode_strings)
        }


class DecompilerSuite:
    """Main decompiler suite"""
    
    def __init__(self, exe_path: str, out_dir: str = "decompiled_output"):
        self.exe_path = exe_path
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.report = {}
    
    def run_full_analysis(self, options: Dict = None):
        """Run complete analysis"""
        if options is None:
            options = {
                "resources": True,
                "carve": True,
                "security": True,
                "strings": True,
                "dotnet": True,
                "debug": True
            }
        
        with open(self.exe_path, 'rb') as f:
            data = f.read()
        
        self.report["basic_info"] = {
            "filename": Path(self.exe_path).name,
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        }
        
        pe = pefile.PE(self.exe_path)
        
        self.report["imports"] = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode('utf-8', errors='ignore')
                self.report["imports"][dll_name] = [func.name.decode('utf-8', errors='ignore') if func.name else f"Ordinal_{func.ordinal}" for func in dll.imports]
        
        self.report["basic_info"]["sections"] = len(pe.sections)
        
        if options["security"]:
            self.report["security"] = SecurityAnalyzer.detect_packing(pe)
        
        if options["resources"]:
            res_dir = os.path.join(self.out_dir, "resources")
            os.makedirs(res_dir, exist_ok=True)
            self.report["resources"] = ResourceExtractor.extract_resources(self.exe_path, res_dir)
        
        if options["carve"]:
            carve_dir = os.path.join(self.out_dir, "carved")
            engine = CarvingEngine(data, carve_dir)
            engine.carve_all()
        
        if options["strings"]:
            strings = ConfigExtractor.extract_strings(data)
            self.report["strings"] = {
                "ascii_count": strings["ascii_count"],
                "unicode_count": strings["unicode_count"]
            }

            with open(os.path.join(self.out_dir, "ascii_strings.txt"), 'w') as f:
                f.write('\n'.join(strings["ascii"]))
            with open(os.path.join(self.out_dir, "unicode_strings.txt"), 'w') as f:
                f.write('\n'.join(strings["unicode"]))

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
  python decompiler_suite.py --no-carve --no-dotnet
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
