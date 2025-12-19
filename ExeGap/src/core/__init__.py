"""
ExeGap Core Analysis Engine
Professional binary analysis and decompilation toolkit
"""
__version__ = "3.0.1"
__author__ = "Brutality"
__description__ = "Advanced PE Binary Analysis & Extraction Suite"

from .pe_analyzer import PEAnalyzer
from .security_analyzer import SecurityAnalyzer
from .file_carver import FileCarver
from .dotnet_handler import DotNetHandler
from .config_extractor import ConfigExtractor

__all__ = [
    'PEAnalyzer',
    'SecurityAnalyzer',
    'FileCarver',
    'DotNetHandler',
    'ConfigExtractor',
]
