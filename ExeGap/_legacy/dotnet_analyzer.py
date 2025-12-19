#!/usr/bin/env python3
"""
.NET Assembly Analyzer - Extract metadata, types, methods from .NET binaries
"""
import struct
import os
import json
import logging
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class CLRMetadataParser:
    """Parse Common Language Runtime metadata"""

    TABLE_IDS = {
        0: "Module",
        1: "TypeRef", 
        2: "TypeDef",
        3: "FieldPtr",
        4: "Field",
        5: "MethodPtr",
        6: "Method",
        7: "ParamPtr",
        8: "Param",
        9: "InterfaceImpl",
        10: "MemberRef",
        11: "Constant",
        12: "CustomAttribute",
        13: "FieldMarshal",
        14: "DeclSecurity",
        15: "ClassLayout",
        16: "FieldLayout",
        17: "StandAloneSig",
        18: "EventMap",
        19: "EventPtr",
        20: "Event",
        21: "PropertyMap",
        22: "PropertyPtr",
        23: "Property",
        24: "MethodSemantics",
        25: "MethodImpl",
        26: "ModuleRef",
        27: "TypeSpec",
        28: "ImplMap",
        29: "FieldRVA",
        30: "ENCLog",
        31: "ENCMap",
        32: "Assembly",
        33: "AssemblyProcessor",
        34: "AssemblyOS",
        35: "AssemblyRef",
        36: "AssemblyRefProcessor",
        37: "AssemblyRefOS",
        38: "File",
        39: "ExportedType",
        40: "ManifestResource",
        41: "NestedClass",
        42: "GenericParam",
        43: "MethodSpec",
        44: "GenericParamConstraint",
    }
    
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.metadata = {}
    
    def read_bytes(self, n: int) -> bytes:
        """Read n bytes and advance position"""
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result
    
    def read_u32(self) -> int:
        return struct.unpack('<I', self.read_bytes(4))[0]
    
    def read_u16(self) -> int:
        return struct.unpack('<H', self.read_bytes(2))[0]
    
    def extract_assembly_info(self, data: bytes) -> Dict:
        """Extract assembly metadata"""
        info = {}

        clr_offset = data.find(b'BSJB')
        if clr_offset != -1:
            info["clr_header"] = clr_offset
            self.pos = clr_offset

            major = self.read_u16()
            minor = self.read_u16()
            info["clr_version"] = f"v{major}.{minor}"

        
        return info


class ManifestExtractor:
    """Extract embedded manifests"""
    
    @staticmethod
    def extract_manifest(data: bytes) -> Dict:
        manifest = {"found": False, "content": None}
        
        manifest_start = data.find(b"<?xml")
        if manifest_start == -1:
            manifest_start = data.find(b"<assembly")
        
        if manifest_start != -1:
            manifest_end = data.find(b"</assembly>", manifest_start)
            if manifest_end != -1:
                manifest["found"] = True
                manifest["content"] = data[manifest_start:manifest_end + len(b"</assembly>")].decode('utf-8', errors='ignore')
        
        return manifest


class DotNetDecompiler:
    """Main .NET decompiler interface"""
    
    def __init__(self, assembly_path: str):
        self.assembly_path = assembly_path
    
    def decompile(self) -> Dict:
        """Perform decompilation analysis"""
        with open(self.assembly_path, 'rb') as f:
            data = f.read()
        
        results = {
            "file": os.path.basename(self.assembly_path),
            "size": len(data),
            "metadata": CLRMetadataParser(data).extract_assembly_info(data),
            "manifest": ManifestExtractor.extract_manifest(data),
            "il_code_sections": []
        }
        
        return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description=".NET Assembly Analyzer")
    parser.add_argument('assembly', help='Path to .NET assembly')
    parser.add_argument('-o', '--out', help='Output JSON file')
    args = parser.parse_args()
    
    decompiler = DotNetDecompiler(args.assembly)
    result = decompiler.decompile()
    
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(result, f, indent=2)
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
