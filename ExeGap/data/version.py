"""
ExeGap Version Information and Metadata
"""

__title__ = "ExeGap"
__version__ = "3.0.0"
__author__ = "ExeGap Development Team"
__license__ = "MIT"
__description__ = "Advanced PE Binary Analysis & Decompilation Suite"
__url__ = "https://github.com/exegap/exegap"

VERSION_INFO = {
    "major": 3,
    "minor": 0,
    "patch": 0,
    "build": "professional",
    "release_date": "2024",
}

FEATURES = [
    "PE Binary Analysis",
    "Security Analysis",
    "File Carving",
    ".NET Assembly Analysis",
    "API Hook Detection",
    "Malware Behavior Classification",
    "Resource Extraction",
    "Professional GUI",
    "Web Dashboard",
    "Batch Processing",
    "Multiple Report Formats",
]

CAPABILITIES = {
    "packing_detection": "Advanced entropy and signature-based detection",
    "security_analysis": "Malware behavior classification and API risk analysis",
    "file_carving": "40+ file type signatures with smart carving",
    "dotnet_analysis": "CLR metadata and IL code analysis",
    "resource_extraction": "Complete PE resource enumeration",
    "string_analysis": "ASCII and Unicode string extraction with intelligence",
}

print(f"""
╔═════════════════════════════════════════════════════════════════════╗
║                    EXEGAP {__version__}                        ║
║         Advanced PE Binary Analysis & Decompilation Suite         ║
╚═════════════════════════════════════════════════════════════════════╝
""")