#!/usr/bin/env python3
"""
Advanced Config & Secret Extractor Module
Extracts configuration, credentials, and secrets from binaries
Consolidates functionality from config_extractor.py
"""
import re
import json
import hashlib
import logging
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    """Represents a discovered secret"""
    type_: str
    value: str
    offset: int
    category: str
    confidence: float
    context: str = ""


class ConfigExtractor:
    """Extract configuration and sensitive data from binaries"""

    PATTERNS = {
        "api_key": {
            "patterns": [
                r"(?i)(api[_-]?key|apikey|api-key|auth[_-]?key|token)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?",
                r"(?i)x-api-key[\s:=]+([A-Za-z0-9\-_]+)",
                r"(?i)authorization[\s:=]+bearer[\s]+([A-Za-z0-9\-_.]+)",
            ],
            "category": "API Credentials",
            "confidence": 0.95
        },
        "password": {
            "patterns": [
                r"(?i)(password|passwd|pwd|pass)[\s:=]+['\"]?([A-Za-z0-9!@#$%^&*\-_]{6,})['\"]?",
                r"(?i)(dbpassword|db_password|database_password)[\s:=]+['\"]([^\"']+)['\"]",
                r"(?i)(admin_pass|adminpass)[\s:=]+['\"]([^\"']+)['\"]",
            ],
            "category": "Credentials",
            "confidence": 0.90
        },
        "username": {
            "patterns": [
                r"(?i)(username|user|uid|email)[\s:=]+['\"]?([A-Za-z0-9.@\-_]{4,})['\"]?",
                r"(?i)(admin|root)[\s:=]+['\"]?([A-Za-z0-9\-_]+)['\"]?",
            ],
            "category": "Credentials",
            "confidence": 0.85
        },
        "url": {
            "patterns": [
                r"https?://[^\s\x00]{10,}",
                r"ftp://[^\s\x00]{10,}",
                r"ldap://[^\s\x00]{10,}",
            ],
            "category": "Network Endpoint",
            "confidence": 0.88
        },
        "ip_address": {
            "patterns": [
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            ],
            "category": "Network Address",
            "confidence": 0.92
        },
        "domain": {
            "patterns": [
                r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}",
            ],
            "category": "Domain Name",
            "confidence": 0.80
        },
        "email": {
            "patterns": [
                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}",
            ],
            "category": "Contact Information",
            "confidence": 0.90
        },
        "phone": {
            "patterns": [
                r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
            ],
            "category": "Contact Information",
            "confidence": 0.75
        },
        "bitcoin_address": {
            "patterns": [
                r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b",
            ],
            "category": "Cryptocurrency",
            "confidence": 0.95
        },
        "ethereum_address": {
            "patterns": [
                r"\b0x[a-fA-F0-9]{40}\b",
            ],
            "category": "Cryptocurrency",
            "confidence": 0.93
        },
        "private_key": {
            "patterns": [
                r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
                r"-----BEGIN PRIVATE KEY-----",
                r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
            ],
            "category": "Cryptographic Key",
            "confidence": 0.99
        },
        "aws_access_key": {
            "patterns": [
                r"AKIA[0-9A-Z]{16}",
            ],
            "category": "Cloud Credentials",
            "confidence": 0.98
        },
        "connection_string": {
            "patterns": [
                r"(?i)(server|host)[\s:=]+['\"]?([A-Za-z0-9\-_.]+)['\"]?;(?:.*?)(?:user|uid)[\s:=]+['\"]?([A-Za-z0-9\-_]+)['\"]?",
            ],
            "category": "Database Config",
            "confidence": 0.90
        },
        "registry_path": {
            "patterns": [
                r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\x00\s]+",
            ],
            "category": "System Configuration",
            "confidence": 0.85
        },
        "file_path": {
            "patterns": [
                r"(?:C:|D:|E:)\\[A-Za-z0-9\-_\\\.]+\.[A-Za-z0-9]{2,4}",
                r"/(?:home|usr|var|etc|opt)/[A-Za-z0-9\-_/\.]+",
            ],
            "category": "File Path",
            "confidence": 0.75
        },
        "slack_webhook": {
            "patterns": [
                r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9\-_]{24}",
            ],
            "category": "API Credentials",
            "confidence": 0.97
        },
        "jwt_token": {
            "patterns": [
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            ],
            "category": "Authentication Token",
            "confidence": 0.96
        },
        "generic_secret": {
            "patterns": [
                r"(?i)(secret|client_secret|oauth_secret)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?",
            ],
            "category": "Secret",
            "confidence": 0.85
        },
    }
    
    REDACTED_PATTERNS = [
        r"[A-Za-z0-9+/]{40,}={0,2}",
        r"[A-Fa-f0-9]{32,}",
    ]
    
    def __init__(self):
        """Initialize config extractor"""
        self.findings: List[SecretFinding] = []
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance"""
        for pattern_type, config in self.PATTERNS.items():
            compiled = []
            for pattern in config["patterns"]:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE | re.DOTALL))
                except re.error as e:
                    logger.warning(f"Failed to compile pattern {pattern_type}: {e}")
            self.compiled_patterns[pattern_type] = (compiled, config)
    
    def extract_from_binary(self, data: bytes, offset: int = 0) -> List[SecretFinding]:
        """Extract secrets from binary data"""
        self.findings = []

        string_data = self._extract_strings(data)
        
        for pattern_type, (compiled_patterns, config) in self.compiled_patterns.items():
            for pattern in compiled_patterns:
                try:
                    for match in pattern.finditer(string_data):
                        match_offset = offset + data.find(match.group(0).encode('utf-8', errors='ignore'))
                        
                        finding = SecretFinding(
                            type_=pattern_type,
                            value=match.group(0),
                            offset=match_offset,
                            category=config["category"],
                            confidence=config["confidence"],
                            context=self._get_context(string_data, match.start(), 50)
                        )
                        self.findings.append(finding)
                except Exception as e:
                    logger.debug(f"Pattern matching error for {pattern_type}: {e}")
        
        logger.info(f"Found {len(self.findings)} configuration/secret patterns")
        return self.findings
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> str:
        """Extract readable ASCII and UTF-16 strings from binary"""
        strings = []

        current_string = bytearray()
        for byte in data:
            if 32 <= byte <= 126:
                current_string.append(byte)
            elif current_string:
                if len(current_string) >= min_length:
                    strings.append(current_string.decode('ascii', errors='ignore'))
                current_string = bytearray()

        for i in range(0, len(data) - 1, 2):
            try:
                char_pair = data[i:i+2]
                if char_pair[1] == 0 and 32 <= char_pair[0] <= 126:
                    if current_string:
                        if len(current_string) >= min_length:
                            strings.append(current_string.decode('utf-16-le', errors='ignore'))
                        current_string = bytearray()
                    current_string.append(char_pair[0])
            except:
                pass
        
        return "\n".join(strings)
    
    def _get_context(self, data: str, position: int, context_len: int) -> str:
        """Get context around matched position"""
        start = max(0, position - context_len)
        end = min(len(data), position + context_len)
        context = data[start:end]
        return context.replace('\x00', ' ').replace('\n', ' ')[:100]
    
    def extract_hardcoded_strings(self, data: bytes) -> Dict[str, List[str]]:
        """Extract hardcoded strings by category"""
        categorized = defaultdict(list)
        
        for finding in self.findings:
            categorized[finding.category].append({
                "value": finding.value,
                "offset": hex(finding.offset),
                "confidence": finding.confidence
            })
        
        return dict(categorized)
    
    def generate_iocs(self) -> Dict[str, List[str]]:
        """Generate Indicators of Compromise from extracted data"""
        iocs = defaultdict(list)
        
        for finding in self.findings:
            if finding.type_ == "url":
                iocs["urls"].append(finding.value)
            elif finding.type_ == "ip_address":
                iocs["ips"].append(finding.value)
            elif finding.type_ == "domain":
                iocs["domains"].append(finding.value)
            elif finding.type_ in ["bitcoin_address", "ethereum_address"]:
                iocs["crypto_wallets"].append(finding.value)
            elif finding.type_ == "email":
                iocs["emails"].append(finding.value)
        
        return dict(iocs)
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy to detect encoded/encrypted data"""
        if not data:
            return 0.0
        
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in freq.values():
            probability = count / data_len
            entropy -= probability * (probability ** 0.5 if probability > 0 else 0)
        
        return entropy
    
    def get_report(self) -> Dict[str, Any]:
        """Generate comprehensive extraction report"""
        by_category = defaultdict(list)
        for finding in self.findings:
            by_category[finding.category].append(asdict(finding))
        
        report = {
            "total_findings": len(self.findings),
            "by_category": dict(by_category),
            "iocs": self.generate_iocs(),
            "high_confidence": [asdict(f) for f in self.findings if f.confidence >= 0.90],
            "findings_count_by_type": self._count_by_type(),
        }
        
        return report
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count findings by type"""
        counts = defaultdict(int)
        for finding in self.findings:
            counts[finding.type_] += 1
        return dict(counts)
    
    def export_findings(self, format_: str = "json") -> str:
        """Export findings in specified format"""
        if format_ == "json":
            findings_dict = [asdict(f) for f in self.findings]
            return json.dumps(findings_dict, indent=2, default=str)
        elif format_ == "csv":
            lines = ["Type,Value,Offset,Category,Confidence,Context"]
            for f in self.findings:
                lines.append(f'{f.type_},"{f.value}",{hex(f.offset)},{f.category},{f.confidence},"{f.context}"')
            return "\n".join(lines)
        elif format_ == "txt":
            lines = []
            current_category = None
            for f in sorted(self.findings, key=lambda x: x.category):
                if f.category != current_category:
                    current_category = f.category
                    lines.append(f"\n=== {current_category.upper()} ===")
                lines.append(f"[{hex(f.offset)}] {f.value[:80]}")
            return "\n".join(lines)
        
        return json.dumps([asdict(f) for f in self.findings], indent=2, default=str)