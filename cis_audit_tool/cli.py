import argparse
import sys
from .config import load_config
from .logger import setup_logger
from .output import generate_output
from .linux.audit_checks import run_linux_audit
from .windows.audit_checks import run_windows_audit

def main():
    parser = argparse.ArgumentParser(description="Automated CIS Benchmark Audit Tool", add_help=True)
    
    # Add arguments
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

    # Load config
    config = load_config(args.config)

    # Set up logger
    logger = setup_logger(debug=args.debug)

    # Determine OS and run audit
    if sys.platform == "linux":
        results = run_linux_audit(config, args.level, args.include, args.exclude)
    elif sys.platform == "win32":
        results = run_windows_audit(config, args.level, args.include, args.exclude)
    else:
        logger.error("Unsupported operating system")
        sys.exit(1)

    # Generate output
    output_format = "text"  # Default
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

    generate_output(results, output_format)

if __name__ == "__main__":
    main()