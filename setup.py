from setuptools import setup, find_packages

setup(
    name="cis_audit_tool",
    version="1.0",
    packages=find_packages(),  # Automatically find packages in the directory
    install_requires=["pyyaml"],  # List of dependencies
    entry_points={
        "console_scripts": [
            "cis-audit-tool=cis_audit_tool.cli:main"  # Command-line entry point
        ]
    },
    python_requires=">=3.6",  # Minimum Python version
)