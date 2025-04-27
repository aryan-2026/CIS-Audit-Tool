# cis_audit_tool/linux/__init__.py

# Import key functions or classes to make them available at the subpackage level
from .audit_checks import run_linux_audit
from .benchmarks import LINUX_BENCHMARKS

# Define __all__ to control what gets imported with `from cis_audit_tool.linux import *`
__all__ = ["run_linux_audit", "LINUX_BENCHMARKS"]