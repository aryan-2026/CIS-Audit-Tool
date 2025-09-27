# CIS Audit Tool

A Python-based tool to automate CIS (Center for Internet Security) benchmark audits.  
The tool inspects system settings, configurations, and compliance parameters and generates a report or log, helping administrators strengthen security posture.

## Features

- Performs automated checks for CIS benchmark controls  
- Logs findings in a structured format  
- Easily extensible: you can add or modify checks  
- Configurable output (logs, reports, etc.)

### Installation

Clone the repository:

```bash
git clone https://github.com/aryan-2026/CIS-Audit-Tool.git
cd CIS-Audit-Tool
pip install -r requirements.txt
python setup.py install
python -m cis_audit_tool.main --help
