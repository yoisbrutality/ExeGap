#!/usr/bin/env python3
"""
Advanced File Carving and Signature Detection
Extract embedded files from binary data using pattern matching
Consolidates functionality from extractor.py and advanced carving
"""
import os
import struct
import logging
import pefile
from typing import List, Tuple, Dict, Any, BinaryIO
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CarveResult:
    """Result of file carving"""
    offset: int
    signature: bytes
    extension: str
    name: str
    size: int = None
    confidence: float = 1.0


class FileCarver:
    """
    Advanced file carver for extracting embedded files
    Supports 40+ file type signatures
    """
    
    SIGNATURES = {
        b"PK\x03\x04": (".zip", "ZIP Archive", True),
        b"PK\x05\x06": (".zip", "ZIP Archive", False),
        b"7z\xBC\xAF\x27\x1C": (".7z", "7-Zip Archive", True),
        b"Rar!\x1A\x07\x00": (".rar", "RAR Archive v5", True),
        b"Rar!\x1A\x07": (".rar", "RAR Archive", True),
        b"\x1F\x8B\x08": (".gz", "GZIP Archive", True),
        b"BZh": (".bz2", "BZIP2 Archive", True),

        b"MZ": (".exe", "PE Executable/DLL", True),
        b"\x7FELF": (".elf", "ELF Binary", True),

        b"\x89PNG\r\n\x1a\n": (".png", "PNG Image", True),
        b"\xFF\xD8\xFF": (".jpg", "JPEG Image", False),
        b"GIF87a": (".gif", "GIF Image", True),
        b"GIF89a": (".gif", "GIF Image", True),
        b"BM": (".bmp", "BMP Image", True),
        b"II\x2A\x00": (".tiff", "TIFF Image", True),
        b"MM\x00\x2A": (".tiff", "TIFF Image", True),
        b"RIFF": (".wav", "RIFF Audio", False),

        b"%PDF": (".pdf", "PDF Document", True),
        b"PK\x03\x04\x14\x00\x08": (".docx", "DOCX Document", True),
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": (".doc", "DOC Document", True),

        b"ID3": (".mp3", "MP3 Audio", False),
        b"\xFF\xFB": (".mp3", "MP3 Audio", False),
        b"\xFF\xFA": (".mp3", "MP3 Audio", False),
        b"\x49\x44\x33": (".mp3", "MP3 Audio", True),

        b"\xCA\xFE\xBA\xBE": (".class", "Java Class File", True),

        b"SQLite format 3": (".db", "SQLite Database", True),
        b"\x4D\x53\x43\x46": (".cab", "Cabinet Archive", True),
        b"\x50\x4B\x03\x04": (".apk", "Android Package", True),
    }
    
    def __init__(self, data: bytes, output_dir: str = "carved_files"):
        """Initialize file carver"""
        self.data = data
        self.output_dir = output_dir
        self.results = []
        
        os.makedirs(output_dir, exist_ok=True)
    
    def extract_pe_resources(self, pe_path: str) -> Dict[str, Any]:
        """Extract PE resources from binary (from extractor.py)"""
        resources = {
            "total": 0,
            "extracted": 0,
            "resources": [],
            "errors": [],
        }
        
        try:
            pe = pefile.PE(pe_path)
        except Exception as e:
            logger.error(f"pefile failed to parse PE: {e}")
            resources["errors"].append(str(e))
            return resources
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            logger.debug("No resources directory found")
            return resources
        
        res_count = 0
        try:
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    if hasattr(entry, 'directory'):
                        for res in entry.directory.entries:
                            if hasattr(res, 'directory'):
                                for res_lang in res.directory.entries:
                                    data_rva = res_lang.data.struct.OffsetToData
                                    size = res_lang.data.struct.Size
                                    
                                    try:
                                        data = pe.get_data(data_rva, size)
                                        resource_name = f"resource_{res_count:03d}.bin"
                                        
                                        resource_info = {
                                            "id": res_count,
                                            "name": resource_name,
                                            "size": size,
                                            "offset": hex(data_rva),
                                        }
                                        resources["resources"].append(resource_info)

                                        if hasattr(self, 'output_dir'):
                                            out_path = os.path.join(self.output_dir, resource_name)
                                            with open(out_path, 'wb') as f:
                                                f.write(data)
                                            resources["extracted"] += 1
                                        
                                        res_count += 1
                                    except Exception as e:
                                        logger.debug(f"Resource extraction error: {e}")
                except Exception as e:
                    logger.debug(f"Resource entry error: {e}")
        except Exception as e:
            resources["errors"].append(f"Resource parsing error: {str(e)}")
        
        resources["total"] = res_count
        return resources
    
    def carve_all(self) -> List[CarveResult]:
        """Carve all embedded files from data"""
        logger.info("Starting file carving analysis...")
        
        for signature, (ext, name, is_fixed) in self.SIGNATURES.items():
            offset = 0
            while True:
                offset = self.data.find(signature, offset)
                if offset == -1:
                    break
                
                result = CarveResult(
                    offset=offset,
                    signature=signature,
                    extension=ext,
                    name=name,
                    confidence=0.95 if is_fixed else 0.75
                )
                self.results.append(result)
                logger.debug(f"Found {name} at offset {hex(offset)}")
                
                offset += len(signature)
        
        logger.info(f"Carved {len(self.results)} potential files")
        return self.results
    
    def extract_files(self, min_confidence: float = 0.7) -> Dict[str, str]:
        """Extract and save carved files"""
        extracted = {}
        
        for i, result in enumerate(self.results):
            if result.confidence < min_confidence:
                continue

            if i < len(self.results) - 1:
                end_offset = self.results[i + 1].offset
            else:
                end_offset = len(self.data)
            
            file_data = self.data[result.offset:end_offset]
            filename = f"{result.name}_{i:03d}{result.extension}"
            filepath = os.path.join(self.output_dir, filename)
            
            try:
                with open(filepath, 'wb') as f:
                    f.write(file_data)
                
                extracted[filename] = filepath
                logger.info(f"Extracted: {filename} ({len(file_data)} bytes)")
            except Exception as e:
                logger.error(f"Failed to extract {filename}: {e}")
        
        return extracted
    
    def get_summary(self) -> Dict[str, Any]:
        """Get carving summary"""
        file_types = {}
        for result in self.results:
            file_type = result.name
            file_types[file_type] = file_types.get(file_type, 0) + 1
        
        return {
            "total_found": len(self.results),
            "file_types": file_types,
            "results": [
                {
                    "offset": hex(r.offset),
                    "type": r.name,
                    "extension": r.extension,
                    "confidence": r.confidence
                }
                for r in self.results
            ]
        }


class StringExtractor:
    """Extract and analyze strings from binary data"""
    
    def __init__(self, data: bytes):
        """Initialize string extractor"""
        self.data = data
        self.strings = []
    
    def extract_ascii(self, min_length: int = 4) -> List[str]:
        """Extract ASCII strings"""
        ascii_strings = []
        current_string = b""
        
        for byte in self.data:
            if 32 <= byte <= 126 or byte in (9, 10, 13):
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    ascii_strings.append(current_string.decode('ascii', errors='ignore'))
                current_string = b""
        
        self.strings.extend(ascii_strings)
        return ascii_strings
    
    def extract_unicode(self, min_length: int = 4) -> List[str]:
        """Extract Unicode strings"""
        unicode_strings = []
        i = 0
        
        while i < len(self.data) - 1:
            if self.data[i:i+2] == b'\x00\x00':
                i += 2
                continue
            
            try:
                char = self.data[i:i+2].decode('utf-16-le')
                if ord(char) >= 32:
                    current_string = char
                    i += 2
                    
                    while i < len(self.data) - 1:
                        byte_pair = self.data[i:i+2]
                        if byte_pair == b'\x00\x00':
                            break
                        try:
                            next_char = byte_pair.decode('utf-16-le')
                            if ord(next_char) >= 32:
                                current_string += next_char
                            i += 2
                        except:
                            break
                    
                    if len(current_string) >= min_length:
                        unicode_strings.append(current_string)
                else:
                    i += 2
            except:
                i += 2
        
        self.strings.extend(unicode_strings)
        return unicode_strings
    
    def analyze_strings(self) -> Dict[str, Any]:
        """Analyze strings for intelligence"""
        analysis = {
            "total_strings": len(self.strings),
            "urls": [],
            "ips": [],
            "emails": [],
            "paths": [],
            "registry_keys": [],
        }
        
        for string in self.strings:
            if any(proto in string for proto in ['http://', 'https://', 'ftp://']):
                analysis["urls"].append(string)

            if self._is_ip(string):
                analysis["ips"].append(string)

            if '@' in string and '.' in string:
                analysis["emails"].append(string)

            if any(string.startswith(p) for p in ['C:\\', 'HKEY_', 'System32']):
                analysis["paths"].append(string)

            if string.startswith('HKEY_'):
                analysis["registry_keys"].append(string)
        
        return analysis
    
    def _is_ip(self, string: str) -> bool:
        """Check if string is IP address"""
        parts = string.split('.')
        if len(parts) != 4:
            return False
        
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python file_carver.py <BINARY_FILE>")
        sys.exit(1)
    
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    carver = FileCarver(data, "carved_output")
    carver.carve_all()
    carver.extract_files()
    
    import json
    print(json.dumps(carver.get_summary(), indent=2, default=str))
