#!/usr/bin/env python3
import pefile
import struct
import logging
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import os

logger = logging.getLogger(__name__)


@dataclass
class CLRMetadata:
    """CLR Metadata information"""
    version: str
    runtime_version: str
    entry_point: str
    assembly_name: str
    entry_point_token: str = None
    flags: List[str] = None


class DotNetHandler:
    """
    Comprehensive .NET assembly analyzer
    Handles CLR metadata, IL code, and manifests
    """

    CLR_MAGIC = 0x48
    RUNTIME_VERSION_PREFIX = "v"
    
    def __init__(self, filepath: str):
        """Initialize .NET handler"""
        self.filepath = filepath
        self.pe = None
        self.clr_runtime = None
        self.clr_metadata = None
        
        self._load_assembly()
    
    def _load_assembly(self):
        """Load .NET assembly"""
        try:
            self.pe = pefile.PE(self.filepath)
        except Exception as e:
            logger.error(f"Failed to load assembly: {e}")
            raise
    
    def is_dotnet_assembly(self) -> bool:
        """Check if PE is .NET assembly"""
        try:
            return self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']].VirtualAddress > 0
        except:
            return False
    
    def get_clr_metadata(self) -> Dict[str, Any]:
        """Extract CLR metadata"""
        metadata = {
            "is_dotnet": False,
            "runtime_version": "Unknown",
            "assembly_info": {},
            "entry_point": {},
        }
        
        if not self.is_dotnet_assembly():
            return metadata
        
        metadata["is_dotnet"] = True
        
        try:
            cor20 = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']]
            cor20_data = self.pe.get_data(cor20.VirtualAddress, cor20.Size)
            
            if cor20_data:
                major, minor = struct.unpack('<HH', cor20_data[4:8])
                metadata["runtime_version"] = f"v{major}.{minor}"
                
                entry_point_token = struct.unpack('<I', cor20_data[20:24])[0]
                metadata["entry_point"]["token"] = hex(entry_point_token)

                flags = struct.unpack('<I', cor20_data[16:20])[0]
                metadata["flags"] = self._decode_flags(flags)
        except Exception as e:
            logger.debug(f"Error extracting CLR metadata: {e}")

        metadata["sections"] = []
        for section in self.pe.sections:
            if section.Name.startswith(b'.'):
                section_info = {
                    "name": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    "virtual_size": section.VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics),
                }
                metadata["sections"].append(section_info)
        
        return metadata
    
    def _decode_flags(self, flags: int) -> List[str]:
        flag_dict = {
            0x00000001: "IL_ONLY",
            0x00000002: "32BITREQUIRED",
            0x00000004: "IL_LIBRARY",
            0x00000008: "STRONGNAMESIGNED",
            0x00000010: "NATIVE_ENTRYPOINT",
            0x00010000: "TRACKDEBUGDATA",
            0x00020000: "PREFER_32BIT",
        }
        return [name for bit, name in flag_dict.items() if flags & bit]
    
    def extract_resources(self, output_dir: str = "extracted_resources") -> Dict[str, Any]:
        """Extract embedded resources from .NET assembly"""
        resources = {
            "found": False,
            "count": 0,
            "resources": [],
        }
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return resources
        
        os.makedirs(output_dir, exist_ok=True)
        resources["found"] = True
        
        try:
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if not hasattr(resource_type, 'directory'):
                    continue
                for resource_id in resource_type.directory.entries:
                    if not hasattr(resource_id, 'directory'):
                        continue
                    for resource_lang in resource_id.directory.entries:
                        data_rva = resource_lang.data.struct.OffsetToData
                        size = resource_lang.data.struct.Size
                        data = self.pe.get_data(data_rva, size)
                        
                        resource_name = f"resource_{resource_type.id}_{resource_id.id}_{resource_lang.id}.bin"
                        out_path = os.path.join(output_dir, resource_name)
                        with open(out_path, 'wb') as f:
                            f.write(data)
                        
                        resource_info = {
                            "type_id": resource_type.id,
                            "type_name": pefile.RESOURCE_TYPE.get(resource_type.id, "Unknown"),
                            "size": size,
                            "path": out_path,
                        }
                        resources["resources"].append(resource_info)
                        resources["count"] += 1
        except Exception as e:
            logger.debug(f"Error extracting resources: {e}")
        
        return resources
    
    def get_imports_exports(self) -> Dict[str, Any]:
        """Get imported and exported functions"""
        info = {
            "imports": {},
            "exports": [],
        }

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode('utf-8', errors='ignore').rstrip('\x00')
                info["imports"][dll_name] = []
                
                for func in dll.imports:
                    func_name = func.name.decode('utf-8', errors='ignore').rstrip('\x00') if func.name else f"Ordinal_{func.ordinal}"
                    info["imports"][dll_name].append(func_name)

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    "name": export.name.decode('utf-8', errors='ignore').rstrip('\x00') if export.name else "Unknown",
                    "address": hex(export.address),
                }
                info["exports"].append(export_info)
        
        return info
    
    def analyze_il_code_patterns(self) -> Dict[str, Any]:
        """Analyze IL code patterns for behavior"""
        patterns = {
            "reflection": False,
            "dynamic_code": False,
            "obfuscation": False,
            "suspicious_apis": [],
            "detected_patterns": [],
        }
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return patterns

        suspicious = [
            "GetMethod",
            "Invoke",
            "CreateInstance",
            "GetType",
            "Type.GetType",
            "Assembly.Load",
            "Assembly.LoadFrom",
            "DynamicMethod",
            "ILGenerator",
            "Emit",
            "Confuser",
            "Dotfuscator",
        ]
        
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            for func in dll.imports:
                func_name = func.name.decode('utf-8', errors='ignore') if func.name else ""
                
                if any(susp in func_name for susp in suspicious):
                    patterns["detected_patterns"].append(func_name)
                    patterns["suspicious_apis"].append(func_name)
                    if "GetMethod" in func_name or "Invoke" in func_name:
                        patterns["reflection"] = True
                    if "DynamicMethod" in func_name or "ILGenerator" in func_name:
                        patterns["dynamic_code"] = True
                    if "Confuser" in func_name or "Dotfuscator" in func_name:
                        patterns["obfuscation"] = True
        
        return patterns
    
    def get_full_analysis(self) -> Dict[str, Any]:
        """Get complete .NET analysis"""
        return {
            "clr_metadata": self.get_clr_metadata(),
            "resources": self.extract_resources(),
            "imports_exports": self.get_imports_exports(),
            "il_patterns": self.analyze_il_code_patterns(),
        }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dotnet_handler.py <DOTNET_ASSEMBLY>")
        sys.exit(1)
    
    handler = DotNetHandler(sys.argv[1])
    analysis = handler.get_full_analysis()
    print(json.dumps(analysis, indent=2, default=str))
