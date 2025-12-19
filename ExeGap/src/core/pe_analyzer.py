#!/usr/bin/env python3

import pefile
import json
import hashlib
import os
import math
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class PEMetadata:
    filename: str
    file_size: int
    md5_hash: str
    sha256_hash: str
    timestamp: str
    pe_type: str
    compiled_date: str
    subsystem: str
    machine: str
    characteristics: List[str]
    sections_count: int
    imphash: str = None


class PEAnalyzer:
    SUBSYSTEMS = {
        0: "Unknown",
        1: "Native",
        2: "Windows GUI",
        3: "Windows CUI",
        7: "POSIX CUI",
        8: "Windows CE",
        10: "EFI",
        11: "EFI Boot Service",
        12: "EFI Runtime",
    }
    
    MACHINE_TYPES = {
        0x14c: "i386",
        0x8664: "x64",
        0xaa64: "ARM64",
        0x1c0: "ARM",
        0x200: "PowerPC",
    }
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file_data = None
        self.pe = None
        self.metadata = None
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        self._load_pe()
    
    def _load_pe(self):
        """Load and parse PE file"""
        try:
            with open(self.filepath, 'rb') as f:
                self.file_data = f.read()
            self.pe = pefile.PE(data=self.file_data)
        except Exception as e:
            logger.error(f"Failed to load PE file: {e}")
            raise
    
    def get_metadata(self) -> PEMetadata:
        """Extract PE file metadata"""
        if self.metadata:
            return self.metadata
        
        file_size = len(self.file_data)
        md5 = hashlib.md5(self.file_data).hexdigest()
        sha256 = hashlib.sha256(self.file_data).hexdigest()
        
        try:
            compiled_date = datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp).isoformat()
        except ValueError:
            compiled_date = "Invalid timestamp"
        
        pe_type = "64-bit" if self.pe.OPTIONAL_HEADER.Magic == 0x20b else "32-bit"
        subsystem = self.SUBSYSTEMS.get(self.pe.OPTIONAL_HEADER.Subsystem, "Unknown")
        machine = self.MACHINE_TYPES.get(self.pe.FILE_HEADER.Machine, "Unknown")
        
        characteristics = self._get_characteristics()
        sections_count = len(self.pe.sections)
        imphash = self.pe.get_imphash()
        
        self.metadata = PEMetadata(
            filename=Path(self.filepath).name,
            file_size=file_size,
            md5_hash=md5,
            sha256_hash=sha256,
            timestamp=datetime.now().isoformat(),
            pe_type=pe_type,
            compiled_date=compiled_date,
            subsystem=subsystem,
            machine=machine,
            characteristics=characteristics,
            sections_count=sections_count,
            imphash=imphash,
        )
        
        return self.metadata
    
    def _get_characteristics(self) -> List[str]:
        """Get file characteristics"""
        chars = []
        flags = {
            0x0001: "Relocation info stripped",
            0x0002: "Executable image",
            0x0004: "Line numbers stripped",
            0x0008: "Local symbols stripped",
            0x0010: "Aggressive working set trim",
            0x0020: "Large address aware",
            0x0040: "Bytes reversed",
            0x0100: "32-bit machine",
            0x0200: "Debugging disabled",
            0x1000: "Removable run from swap",
            0x2000: "Network run from swap",
            0x4000: "System file",
            0x8000: "DLL file",
        }
        
        for flag, desc in flags.items():
            if self.pe.FILE_HEADER.Characteristics & flag:
                chars.append(desc)
        
        return chars
    
    def get_sections(self) -> List[Dict[str, Any]]:
        """Get section information"""
        sections = []
        for section in self.pe.sections:
            try:
                data = self.pe.get_data(section.VirtualAddress, section.SizeOfRawData)
                section_info = {
                    "name": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics),
                    "entropy": self._calculate_entropy(data),
                    "md5": hashlib.md5(data).hexdigest(),
                }
                sections.append(section_info)
            except:
                logger.warning(f"Failed to process section {section.Name}")
        overlay_offset = self.pe.get_overlay_data_start_offset()
        if overlay_offset:
            overlay_data = self.file_data[overlay_offset:]
            sections.append({
                "name": "OVERLAY",
                "virtual_address": "N/A",
                "virtual_size": len(overlay_data),
                "raw_size": len(overlay_data),
                "characteristics": "N/A",
                "entropy": self._calculate_entropy(overlay_data),
                "md5": hashlib.md5(overlay_data).hexdigest(),
            })
        return sections
    
    def get_imports(self) -> Dict[str, List[str]]:
        """Extract imported functions"""
        imports = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode('utf-8', errors='ignore').rstrip('\x00')
                imports[dll_name] = []
                for func in dll.imports:
                    func_name = func.name.decode('utf-8', errors='ignore').rstrip('\x00') if func.name else f"Ordinal_{func.ordinal}"
                    imports[dll_name].append(func_name)
        return imports
    
    def get_exports(self) -> List[Dict[str, Any]]:
        """Extract exported functions"""
        exports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for i, export in enumerate(self.pe.DIRECTORY_ENTRY_EXPORT.symbols):
                exports.append({
                    "ordinal": i + 1,
                    "address": hex(export.address),
                    "name": export.name.decode('utf-8', errors='ignore').rstrip('\x00') if export.name else "Unknown",
                })
        return exports
    
    def get_resources(self) -> Dict[str, Any]:
        """Extract resource directory information"""
        resources = {"count": 0, "types": []}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resource_info = {
                    "type_id": resource_type.id,
                    "name": pefile.RESOURCE_TYPE.get(resource_type.id, "Unknown"),
                    "entries": len(resource_type.directory.entries) if hasattr(resource_type, 'directory') else 0,
                }
                resources["types"].append(resource_info)
                resources["count"] += resource_info["entries"]
        return resources
    
    def get_debug_info(self) -> Dict[str, Any]:
        """Extract debug information"""
        debug_info = {"present": False, "details": []}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
            debug_info["present"] = True
            for debug in self.pe.DIRECTORY_ENTRY_DEBUG:
                debug_info["details"].append({
                    "type": debug.struct.Type,
                    "size": debug.struct.SizeOfData,
                    "address": hex(debug.struct.AddressOfRawData),
                })
        return debug_info
    
    def _calculate_entropy(self, data: bytes) -> float:
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
        
        return round(entropy, 2)
    
    def get_full_analysis(self) -> Dict[str, Any]:
        """Get complete PE analysis"""
        return {
            "metadata": asdict(self.get_metadata()),
            "sections": self.get_sections(),
            "imports": self.get_imports(),
            "exports": self.get_exports(),
            "resources": self.get_resources(),
            "debug_info": self.get_debug_info(),
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python pe_analyzer.py <PE_FILE>")
        sys.exit(1)
    
    analyzer = PEAnalyzer(sys.argv[1])
    analysis = analyzer.get_full_analysis()
    print(json.dumps(analysis, indent=2, default=str))
