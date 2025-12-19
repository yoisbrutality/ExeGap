#!/usr/bin/env python3
import re
import json
import hashlib
import logging
import math
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
    }

    def __init__(self):
        self.findings: List[SecretFinding] = []
        self.compiled_patterns = {}
        for key, info in self.PATTERNS.items():
            self.compiled_patterns[key] = [re.compile(p) for p in info["patterns"]]

    def extract_from_binary(self, data: bytes):
        """Extract secrets from binary data"""
        self.findings.clear()
        strings_data = self._extract_strings(data)
        
        for key, patterns in self.compiled_patterns.items():
            category = self.PATTERNS[key]["category"]
            confidence = self.PATTERNS[key]["confidence"]
            
            for pattern in patterns:
                for match in pattern.finditer(strings_data):
                    if len(match.groups()) < 1:
                        continue
                    value = match.group(1)
                    if len(value) < 6 or value.lower() in ["password", "admin"]:
                        continue
                    finding = SecretFinding(
                        type_=key,
                        value=value,
                        offset=match.start(),
                        category=category,
                        confidence=confidence,
                        context=self._get_context(strings_data, match.start(), 50)
                    )
                    self.findings.append(finding)

    def _extract_strings(self, data: bytes, min_length: int = 4) -> str:
        """Extract ASCII and Unicode strings"""
        strings = []

        current_string = bytearray()
        for byte in data:
            if 32 <= byte <= 126:
                current_string.append(byte)
            elif current_string:
                if len(current_string) >= min_length:
                    strings.append(current_string.decode('ascii', errors='ignore'))
                current_string = bytearray()

        current_string = ''
        i = 0
        while i < len(data) - 1:
            byte_pair = data[i:i+2]
            if byte_pair[1] == 0 and 32 <= byte_pair[0] <= 126:
                current_string += chr(byte_pair[0])
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ''
            i += 2

        return "\n".join(strings)
    
    def _get_context(self, data: str, position: int, context_len: int) -> str:
        start = max(0, position - context_len)
        end = min(len(data), position + context_len)
        context = data[start:end]
        return context.replace('\x00', ' ').replace('\n', ' ')[:100]
    
    def extract_hardcoded_strings(self, data: bytes) -> Dict[str, List[str]]:
        categorized = defaultdict(list)
        
        for finding in self.findings:
            categorized[finding.category].append({
                "value": finding.value,
                "offset": hex(finding.offset),
                "confidence": finding.confidence
            })
        
        return dict(categorized)
    
    def generate_iocs(self) -> Dict[str, List[str]]:
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
        
        return entropy
    
    def get_report(self) -> Dict[str, Any]:
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
        counts = defaultdict(int)
        for finding in self.findings:
            counts[finding.type_] += 1
        return dict(counts)
    
    def export_findings(self, format_: str = "json") -> str:
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
        elif format_ == "md":
            md = "# Secret Findings\n"
            for category, findings in defaultdict(list).items():
                md += f"## {category}\n"
                for f in findings:
                    md += f"- **{f['type_']}**: {f['value']} (Confidence: {f['confidence']})\n"
            return md
        return json.dumps([asdict(f) for f in self.findings], indent=2, default=str)
