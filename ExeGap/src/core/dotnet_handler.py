#!/usr/bin/env python3
"""
.NET Assembly Analysis and Decompilation
CLR metadata parsing and IL code analysis
"""
import pefile
import struct
import logging
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

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
            if not hasattr(self.pe, 'DIRECTORY_ENTRY_COM_PLUS_RUNTIME_HEADER'):
                return False
            return self.pe.DIRECTORY_ENTRY_COM_PLUS_RUNTIME_HEADER.cb > 0
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
            if hasattr(self.pe, 'DIRECTORY_ENTRY_COM_PLUS_RUNTIME_HEADER'):
                header = self.pe.DIRECTORY_ENTRY_COM_PLUS_RUNTIME_HEADER
                runtime_dir = self.pe.get_data(header.MetaData, 100)
                
                if runtime_dir:
                    version_offset = struct.unpack('<I', runtime_dir[12:16])[0]
                    version_data = runtime_dir[version_offset:version_offset+20]
                    metadata["runtime_version"] = version_data.decode('utf-8', errors='ignore').strip('\x00')

                    entry_point_token = struct.unpack('<I', runtime_dir[28:32])[0]
                    metadata["entry_point"]["token"] = hex(entry_point_token)
                    metadata["entry_point"]["rva"] = hex(entry_point_token & 0xFFFFFF)
        except Exception as e:
            logger.debug(f"Error extracting CLR metadata: {e}")

        metadata["sections"] = []
        for section in self.pe.sections:
            if section.Name.startswith(b'.'):
                section_info = {
                    "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    "virtual_size": section.VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics),
                }
                metadata["sections"].append(section_info)
        
        return metadata
    
    def extract_resources(self) -> Dict[str, Any]:
        """Extract embedded resources from .NET assembly"""
        resources = {
            "found": False,
            "count": 0,
            "resources": [],
        }
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return resources
        
        resources["found"] = True
        
        try:
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resource_info = {
                    "type_id": resource_type.id,
                    "type_name": pefile.RESOURCE_TYPE.get(resource_type.id, "Unknown"),
                    "entries": len(resource_type.directory.entries) if hasattr(resource_type, 'directory') else 0,
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
                dll_name = dll.dll.decode('utf-8', errors='ignore')
                info["imports"][dll_name] = []
                
                for func in dll.imports:
                    func_name = func.name.decode('utf-8', errors='ignore') if func.name else f"Ordinal_{func.ordinal}"
                    info["imports"][dll_name].append(func_name)

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for export in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    "name": export.name.decode('utf-8', errors='ignore') if export.name else "Unknown",
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
        ]
        
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            for func in dll.imports:
                func_name = func.name.decode('utf-8', errors='ignore') if func.name else ""
                
                if any(susp in func_name for susp in suspicious):
                    patterns["detected_patterns"].append(func_name)
                    if "GetMethod" in func_name or "Invoke" in func_name:
                        patterns["reflection"] = True
                    if "DynamicMethod" in func_name or "ILGenerator" in func_name:
                        patterns["dynamic_code"] = True
        
        return patterns
    
    def get_full_analysis(self) -> Dict[str, Any]:
        """Get complete .NET analysis"""
        return {
            "clr_metadata": self.get_clr_metadata(),
            "resources": self.extract_resources(),
            "imports_exports": self.get_imports_exports(),
            "il_patterns": self.analyze_il_code_patterns(),
        }


class ResourceExtractor:
    """Extract and analyze resources from PE files"""
    
    def __init__(self, pe_object, output_dir: str = "extracted_resources"):
        """Initialize resource extractor"""
        self.pe = pe_object
        self.output_dir = output_dir
        
        import os
        os.makedirs(output_dir, exist_ok=True)
    
    def extract_all_resources(self) -> Dict[str, Any]:
        """Extract all resources from PE"""
        results = {
            "total": 0,
            "extracted": 0,
            "resources": [],
        }
        
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return results
        
        try:
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = pefile.RESOURCE_TYPE.get(resource_type.id, "Unknown")
                
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for res_data in resource_id.directory.entries:
                                results["total"] += 1
                                
                                resource_info = {
                                    "type": type_name,
                                    "id": resource_id.id,
                                    "language": res_data.id,
                                }
                                results["resources"].append(resource_info)
        except Exception as e:
            logger.error(f"Error extracting resources: {e}")
        
        return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dotnet_handler.py <DOTNET_ASSEMBLY>")
        sys.exit(1)
    
    handler = DotNetHandler(sys.argv[1])
    analysis = handler.get_full_analysis()
    print(json.dumps(analysis, indent=2, default=str))
