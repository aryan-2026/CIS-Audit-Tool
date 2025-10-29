# cis_audit_tool/__init__.py

# Import key modules or functions to make them available at the package level
from .cli import main
from .config import load_config
from .logger import setup_logger
from .output import generate_output

# Define __all__ to control what gets imported with `from cis_audit_tool import *`
__all__ = ["main", "load_config", "setup_logger", "generate_output"]

# Optional: Add package metadata
__version__ = "1.0.0"
__author__ = "Your Name"
__description__ = "Automated CIS Benchmark Audit Tool"