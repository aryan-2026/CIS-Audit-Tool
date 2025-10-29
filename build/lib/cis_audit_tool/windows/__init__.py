# cis_audit_tool/windows/__init__.py

# Import key functions or classes to make them available at the subpackage level
from .audit_checks import run_windows_audit
from .benchmarks import WINDOWS_BENCHMARKS

# Define __all__ to control what gets imported with `from cis_audit_tool.windows import *`
__all__ = ["run_windows_audit", "WINDOWS_BENCHMARKS"]