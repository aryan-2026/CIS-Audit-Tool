import argparse
import sys
from config import load_config
from logger import setup_logger
from output import generate_output
from linux.audit_checks import run_linux_audit
import subprocess
import json


def main():
    parser = argparse.ArgumentParser(description="Automated CIS Benchmark Audit Tool", add_help=True)
    parser.add_argument("--level", choices=["1", "2"], help="Run tests for the specified level only")
    parser.add_argument("--include", nargs="+", help="Space delimited list of tests to include")
    parser.add_argument("--exclude", nargs="+", help="Space delimited list of tests to exclude")
    parser.add_argument("--debug", action="store_true", help="Run script with debug output turned on")
    parser.add_argument("--text", action="store_true", help="Output results as text [default]")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--csv", action="store_true", help="Output results as CSV")
    parser.add_argument("--psv", action="store_true", help="Output results as pipe-separated values")
    parser.add_argument("--tsv", action="store_true", help="Output results as tab-separated values")
    parser.add_argument("--html", action="store_true", help="Output results as HTML table")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s 1.0")
    parser.add_argument("-c", "--config", help="Location of config file to load")

    args = parser.parse_args()

    config = load_config(args.config)
    logger = setup_logger(debug=args.debug)
    results = []  # initialize to avoid UnboundLocalError

    # ---------- LINUX ----------
    if sys.platform == "linux":
        results = run_linux_audit(config, args.level, args.include, args.exclude)

    # ---------- WINDOWS ----------
    elif sys.platform == "win32":
        try:
            ps_command = (
                "Import-Module .\\windows\\modules\\CISChecks.psm1 -Force; "
                "$results = .\\windows\\runner.ps1 -Profile 'cis-windows-11.json'; "
                "$results | ConvertTo-Json -Depth 5"
            )

            completed = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=True
            )

            print("----- PowerShell STDOUT -----")
            print(completed.stdout)
            print("----- PowerShell STDERR -----")
            print(completed.stderr)

            results = json.loads(completed.stdout)

            logger.info("Windows CIS benchmark audit completed successfully.")


        except subprocess.CalledProcessError as e:
            logger.error(f"Error running Windows PowerShell audit: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON output from PowerShell: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during Windows audit: {e}")

    else:
        logger.error("Unsupported operating system")
        sys.exit(1)

    # ---------- OUTPUT FORMAT ----------
    output_format = "text"
    if args.json:
        output_format = "json"
    elif args.csv:
        output_format = "csv"
    elif args.psv:
        output_format = "psv"
    elif args.tsv:
        output_format = "tsv"
    elif args.html:
        output_format = "html"

    # ---------- GENERATE OUTPUT ----------
    if results:
        generate_output(results, output_format)
    else:
        logger.error("No results found — skipping report generation.")
        sys.exit(1)


if __name__ == "__main__":
    main()
