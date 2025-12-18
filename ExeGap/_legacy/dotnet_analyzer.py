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
    
    def read_uint32(self) -> int:
        """Read 32-bit unsigned integer"""
        return struct.unpack('<I', self.read_bytes(4))[0]
    
    def read_uint16(self) -> int:
        """Read 16-bit unsigned integer"""
        return struct.unpack('<H', self.read_bytes(2))[0]
    
    def read_uint8(self) -> int:
        """Read 8-bit unsigned integer"""
        return struct.unpack('B', self.read_bytes(1))[0]
    
    def parse_corheader(self, offset: int) -> Optional[Dict]:
        """Parse CLR Runtime Header"""
        self.pos = offset
        header = {}
        
        header['cb'] = self.read_uint32()
        header['majorRuntimeVersion'] = self.read_uint16()
        header['minorRuntimeVersion'] = self.read_uint16()
        header['metadataRva'] = self.read_uint32()
        header['metadataSize'] = self.read_uint32()
        header['flags'] = self.read_uint32()
        
        return header
    
    def parse_metadata_header(self, offset: int) -> Optional[Dict]:
        """Parse metadata root header"""
        self.pos = offset
        header = {}

        sig = self.read_bytes(4)
        if sig != b'\x42\x53\x4a\x42':
            return None
        
        header['signature'] = sig.hex()
        header['majorVersion'] = self.read_uint16()
        header['minorVersion'] = self.read_uint16()
        header['reserved'] = self.read_uint32()
        header['versionLength'] = self.read_uint32()
        header['version'] = self.read_bytes(header['versionLength']).decode('utf-8', errors='ignore')

        current_pos = self.pos
        aligned = ((current_pos + 3) // 4) * 4
        self.pos = aligned
        
        header['flags'] = self.read_uint16()
        header['numStreams'] = self.read_uint16()
        
        return header
    
    def extract_assembly_info(self, data: bytes) -> Dict:
        """Extract assembly information from .NET binary"""
        info = {
            "version": None,
            "name": None,
            "culture": None,
            "public_key_token": None,
            "types": [],
            "methods": [],
            "fields": [],
            "references": []
        }

        clr_header_offset = None
        for i in range(0, len(data) - 8, 4):
            try:
                if data[i:i+4] == b'\x48\x00\x00\x00':
                    clr_header_offset = i
                    break
            except:
                continue
        
        return info


class AssemblyDisassembler:
    """Disassemble and decompile IL code"""

    IL_OPCODES = {
        0x00: "nop",
        0x01: "ldarg.0",
        0x02: "ldarg.1",
        0x03: "ldarg.2",
        0x04: "ldarg.3",
        0x05: "ldarg.s",
        0x06: "ldarga.s",
        0x07: "starg.s",
        0x08: "ldloc.0",
        0x09: "ldloc.1",
        0x0a: "ldloc.2",
        0x0b: "ldloc.3",
        0x0c: "ldloc.s",
        0x0d: "ldloca.s",
        0x0e: "stloc.0",
        0x0f: "stloc.1",
        0x10: "stloc.2",
        0x11: "stloc.3",
        0x12: "stloc.s",
        0x13: "ldnull",
        0x14: "ldc.i4.m1",
        0x15: "ldc.i4.0",
        0x16: "ldc.i4.1",
        0x17: "ldc.i4.2",
        0x18: "ldc.i4.3",
        0x19: "ldc.i4.4",
        0x1a: "ldc.i4.5",
        0x1b: "ldc.i4.6",
        0x1c: "ldc.i4.7",
        0x1d: "ldc.i4.8",
        0x1e: "ldc.i4.s",
        0x1f: "ldc.i4",
        0x20: "ldc.i8",
        0x21: "ldc.r4",
        0x22: "ldc.r8",
        0x25: "dup",
        0x26: "pop",
        0x27: "jmp",
        0x28: "call",
        0x29: "calli",
        0x2a: "ret",
        0x2b: "br.s",
        0x2c: "brfalse.s",
        0x2d: "brtrue.s",
    }
    
    @staticmethod
    def disassemble_il(il_code: bytes) -> List[str]:
        """Disassemble IL code"""
        result = []
        pos = 0
        
        while pos < len(il_code):
            opcode = il_code[pos]
            mnemonic = AssemblyDisassembler.IL_OPCODES.get(opcode, f"unknown_{opcode:02x}")
            result.append(f"0x{pos:04x}: {mnemonic}")
            pos += 1
        
        return result


class ManifestExtractor:
    """Extract manifest information"""
    
    @staticmethod
    def extract_manifest(data: bytes) -> Dict:
        """Extract application manifest if present"""
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