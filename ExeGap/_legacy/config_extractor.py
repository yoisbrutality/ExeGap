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
                r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
            ],
            "category": "Contact"
        },
        "bitcoin_address": {
            "patterns": [
                r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b",
            ],
            "category": "Cryptocurrency"
        },
        "private_key": {
            "patterns": [
                r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
                r"-----BEGIN PRIVATE KEY-----",
            ],
            "category": "Cryptography"
        },
        "certificate": {
            "patterns": [
                r"-----BEGIN CERTIFICATE-----",
            ],
            "category": "Cryptography"
        },
        "path_windows": {
            "patterns": [
                r"[A-Z]:\\(?:[a-zA-Z0-9._\-\\]+)+",
                r"\\\\[a-zA-Z0-9\-._]+\\[a-zA-Z0-9._\-\\]+",
            ],
            "category": "Paths"
        },
        "registry_key": {
            "patterns": [
                r"HKEY_[A-Z_]+\\[a-zA-Z0-9\\._\-]+",
            ],
            "category": "Windows Registry"
        },
        "string_hash": {
            "patterns": [
                r"\b[a-f0-9]{32}\b",
                r"\b[a-f0-9]{40}\b",
                r"\b[a-f0-9]{64}\b",
            ],
            "category": "Hashes"
        }
    }
    
    @staticmethod
    def extract_secrets(data: bytes, min_confidence: float = 0.5) -> Dict[str, List[Dict]]:
        """Extract secrets and sensitive data from binary"""
        secrets = {}
        
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = data.decode('latin-1', errors='ignore')
        
        for secret_type, config in ConfigExtractor.PATTERNS.items():
            secrets[secret_type] = []
            
            for pattern in config['patterns']:
                try:
                    matches = re.finditer(pattern, text)
                    for match in matches:
                        value = match.group(0)
                        
                        if ConfigExtractor._is_likely_false_positive(value):
                            continue
                        
                        secrets[secret_type].append({
                            "value": value,
                            "offset": match.start(),
                            "category": config['category'],
                            "type": secret_type
                        })
                except Exception as e:
                    logger.debug(f"Error in pattern {secret_type}: {e}")

        return {k: v for k, v in secrets.items() if v}
    
    @staticmethod
    def _is_likely_false_positive(value: str) -> bool:
        """Heuristic to filter false positives"""
        false_positive_patterns = [
            r"^127\.0\.0\.",
            r"^0\.0\.0\.0",
            r"example\.",
            r"test\.",
            r"localhost",
        ]
        
        for pattern in false_positive_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def extract_config_sections(data: bytes) -> Dict[str, List[str]]:
        """Extract likely configuration sections"""
        configs = {
            "json": [],
            "xml": [],
            "ini": [],
            "yaml": []
        }
        
        text = data.decode('utf-8', errors='ignore')
        
        json_pattern = r'\{[^{}]*(?:"[^"]*":\s*[^,}]+,?)*[^{}]*\}'
        configs["json"] = re.findall(json_pattern, text)[:5]
        
        xml_pattern = r'<\w+[^>]*>.*?</\w+>'
        configs["xml"] = re.findall(xml_pattern, text)[:5]

        ini_pattern = r'\[[a-zA-Z0-9_]+\](?:\n[a-zA-Z0-9_]+=.+)*'
        configs["ini"] = re.findall(ini_pattern, text)[:5]
        
        return {k: v for k, v in configs.items() if v}


class HardcodedCredentialFinder:
    """Find hardcoded credentials in binaries"""

    BAD_PATTERNS = {
        "admin_user": [
            "admin", "administrator", "root", "sa", "postgres"
        ],
        "weak_pass": [
            "password", "123456", "admin", "welcome", "letmein",
            "monkey", "dragon", "master", "sunshine", "princess"
        ],
        "env_var": [
            "USERNAME", "PASSWORD", "API_KEY", "DATABASE_PASSWORD"
        ]
    }
    
    @staticmethod
    def find_credentials(data: bytes) -> Dict[str, List[str]]:
        """Find potential hardcoded credentials"""
        text = data.decode('utf-8', errors='ignore')
        findings = {}

        for category, keywords in HardcodedCredentialFinder.BAD_PATTERNS.items():
            findings[category] = []
            for keyword in keywords:
                pattern = r"(?i)" + re.escape(keyword) + r"[\s:=]+['\"]?([^'\"\s\x00]+)['\"]?"
                matches = re.finditer(pattern, text)
                for match in matches:
                    if len(match.group(0)) < 200:
                        findings[category].append(match.group(0))
        
        return {k: list(set(v)) for k, v in findings.items() if v}


class EncodingDetector:
    """Detect encoded/encrypted strings"""
    
    @staticmethod
    def detect_base64(data: bytes) -> List[str]:
        """Detect potential Base64 encoded strings"""
        import base64
        
        b64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
        text = data.decode('utf-8', errors='ignore')
        
        matches = re.finditer(b64_pattern, text)
        decoded = []
        
        for match in matches:
            b64_str = match.group(0)
            try:
                decoded_bytes = base64.b64decode(b64_str)
                if len(decoded_bytes) > 4:
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    if len(decoded_str) > 4 and decoded_str.isprintable():
                        decoded.append({
                            "encoded": b64_str[:50],
                            "decoded": decoded_str[:100]
                        })
            except:
                pass
        
        return decoded
    
    @staticmethod
    def detect_hex_strings(data: bytes) -> List[str]:
        """Detect potential hex-encoded strings"""
        hex_pattern = r"(?:[0-9a-fA-F]{2}){8,}"
        text = data.decode('utf-8', errors='ignore')
        
        matches = re.finditer(hex_pattern, text)
        decoded = []
        
        for match in matches:
            hex_str = match.group(0)
            try:
                decoded_bytes = bytes.fromhex(hex_str)
                if len(decoded_bytes) > 4:
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    if all(32 <= ord(c) < 127 for c in decoded_str if c.isprintable()):
                        decoded.append({
                            "encoded": hex_str[:50],
                            "decoded": decoded_str[:100]
                        })
            except:
                pass
        
        return decoded


class IntelligenceExtractor:
    """Extract actionable intelligence from binaries"""
    
    @staticmethod
    def extract_iocs(data: bytes) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise"""
        iocs = {
            "urls": [],
            "ips": [],
            "domains": [],
            "hashes": [],
            "emails": []
        }
        
        text = data.decode('utf-8', errors='ignore')

        url_pattern = r'https?://[^\s\x00]+'
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
