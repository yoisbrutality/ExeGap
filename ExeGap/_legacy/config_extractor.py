#!/usr/bin/env python3
"""
Advanced Config & Secret Extractor
Extracts configuration, credentials, and secrets from binaries
"""
import re
import json
import hashlib
from typing import List, Dict, Tuple, Optional
import logging
import math

logger = logging.getLogger(__name__)


class ConfigExtractor:
    """Extract configuration and sensitive data from binaries"""
    
    PATTERNS = {
        "api_key": {
            "patterns": [
                r"(?i)(api[_-]?key|apikey|api-key|auth[_-]?key|token)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?",
                r"(?i)x-api-key[\s:=]+([A-Za-z0-9\-_]+)",
            ],
            "category": "API Credentials"
        },
        "password": {
            "patterns": [
                r"(?i)(password|passwd|pwd|pass)[\s:=]+['\"]?([A-Za-z0-9!@#$%^&*\-_]{6,})['\"]?",
                r"(?i)(dbpassword|db_password|database_password)[\s:=]+['\"]([^\"']+)['\"]",
            ],
            "category": "Credentials"
        },
        "username": {
            "patterns": [
                r"(?i)(username|user|uid|email)[\s:=]+['\"]?([A-Za-z0-9.@\-_]{4,})['\"]?",
            ],
            "category": "Credentials"
        },
        "url": {
            "patterns": [
                r"https?://[^\s\x00]{10,}",
                r"ftp://[^\s\x00]{10,}",
            ],
            "category": "Network"
        },
        "ip_address": {
            "patterns": [
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            ],
            "category": "Network"
        },
        "domain": {
            "patterns": [
                r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}",
            ],
            "category": "Network"
        },
        "email": {
            "patterns": [
                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}",
            ],
            "category": "Contact"
        },
        "phone": {
            "patterns": [
                r"(?:(?:\+?(\d{1,3}))?[\s.-]?\(?(?:(\d{3})\)?[\s.-]?)?(\d{3})[\s.-]?(\d{4})(?:\s*(?:ext|x|ext.)\s*(\d{2,5}))?)",
            ],
            "category": "Contact"
        },
        "bitcoin_address": {
            "patterns": [
                r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
            ],
            "category": "Crypto"
        },
        "ethereum_address": {
            "patterns": [
                r"0x[a-fA-F0-9]{40}",
            ],
            "category": "Crypto"
        },
    }
    
    @staticmethod
    def extract_secrets(data: bytes) -> List[Dict]:
        """Extract secrets using patterns"""
        secrets = []
        text = data.decode('utf-8', errors='ignore')
        
        for secret_type, info in ConfigExtractor.PATTERNS.items():
            for pattern in info["patterns"]:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    secrets.append({
                        "type": secret_type,
                        "value": match.group(1) if match.groups() else match.group(0),
                        "offset": match.start(),
                        "category": info["category"]
                    })
        
        return secrets
    
    @staticmethod
    def extract_config_sections(data: bytes) -> List[Dict]:
        """Extract potential config sections"""
        sections = []
        text = data.decode('utf-8', errors='ignore')
        
        config_patterns = [
            r"\[([^\]]+)\]([^\[]+)",
            r"\{.*?\}",
        ]
        
        for pattern in config_patterns:
            for match in re.finditer(pattern, text, re.DOTALL):
                sections.append({
                    "type": "config",
                    "content": match.group(0),
                    "offset": match.start()
                })
        
        return sections


class HardcodedCredentialFinder:
    """Find hardcoded credentials"""
    
    @staticmethod
    def find_credentials(data: bytes) -> List[Dict]:
        """Find potential hardcoded credentials"""
        creds = []
        text = data.decode('utf-8', errors='ignore')
        
        cred_patterns = [
            r"(?i)password\s*=\s*['\"]([^'\"]+)['\"]",
            r"(?i)pwd\s*=\s*['\"]([^'\"]+)['\"]",
            r"(?i)apikey\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        
        for pattern in cred_patterns:
            for match in re.finditer(pattern, text):
                creds.append({
                    "type": "hardcoded_cred",
                    "value": match.group(1),
                    "offset": match.start()
                })
        
        return creds


class EncodingDetector:
    """Detect encoded data"""
    
    @staticmethod
    def detect_base64(data: bytes) -> List[Dict]:
        """Detect potential base64 encoded strings"""
        encoded = []
        text = data.decode('utf-8', errors='ignore')
        
        b64_pattern = r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        
        for match in re.finditer(b64_pattern, text):
            if len(match.group(0)) > 20:
                encoded.append({
                    "type": "base64",
                    "value": match.group(0),
                    "offset": match.start()
                })
        
        return encoded
    
    @staticmethod
    def detect_hex_strings(data: bytes) -> List[Dict]:
        """Detect hex encoded strings"""
        encoded = []
        text = data.decode('utf-8', errors='ignore')
        
        hex_pattern = r'(?:[0-9A-Fa-f]{2}){8,}'
        
        for match in re.finditer(hex_pattern, text):
            encoded.append({
                "type": "hex",
                "value": match.group(0),
                "offset": match.start()
            })
        
        return encoded


class IntelligenceExtractor:
    """Extract intelligence from binaries"""
    
    @staticmethod
    def extract_iocs(data: bytes) -> Dict[str, List[str]]:
        """Extract indicators of compromise"""
        iocs = {
            "urls": [],
            "ips": [],
            "domains": [],
            "emails": [],
            "hashes": []
        }
        
        text = data.decode('utf-8', errors='ignore')
        
        url_pattern = r'https?://[^\s\x00]{10,}'
        iocs["urls"] = list(set(re.findall(url_pattern, text)))[:20]

        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        iocs["ips"] = list(set(re.findall(ip_pattern, text)))[:20]

        domain_pattern = r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}'
        iocs["domains"] = list(set(re.findall(domain_pattern, text, re.IGNORECASE)))[:20]

        email_pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}'
        iocs["emails"] = list(set(re.findall(email_pattern, text)))[:20]

        hash_pattern = r'\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b'
        iocs["hashes"] = list(set(re.findall(hash_pattern, text, re.IGNORECASE)))[:20]
        
        return iocs


class SecretExtractorSuite:
    """Main suite for secret extraction"""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
    
    def extract_all(self) -> Dict:
        """Extract all secrets and configurations"""
        with open(self.binary_path, 'rb') as f:
            data = f.read()
        
        results = {
            "file": self.binary_path,
            "secrets": ConfigExtractor.extract_secrets(data),
            "credentials": HardcodedCredentialFinder.find_credentials(data),
            "base64_encoded": EncodingDetector.detect_base64(data),
            "hex_encoded": EncodingDetector.detect_hex_strings(data),
            "iocs": IntelligenceExtractor.extract_iocs(data),
            "configs": ConfigExtractor.extract_config_sections(data)
        }
        
        return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Advanced Config & Secret Extractor")
    parser.add_argument('binary', help='Binary file to analyze')
    parser.add_argument('-o', '--out', help='Output JSON file')
    args = parser.parse_args()
    
    extractor = SecretExtractorSuite(args.binary)
    results = extractor.extract_all()
    
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.out}")
    else:
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
