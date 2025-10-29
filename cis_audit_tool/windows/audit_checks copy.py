import subprocess
from .benchmarks import WINDOWS_BENCHMARKS  # Import the benchmark definitions


def check_enforce_password_history(min_value=24):
    """
    Check if 'Enforce password history' is set to 24 or more.
    Returns True if the value is 24 or more, False otherwise.
    """
    try:
        # Using net accounts command to get password policy
        result = subprocess.run(
            ["net", "accounts"],
            capture_output=True,
            text=True,
            shell=True  # Required for Windows
        )
        
        # Checking if the command was successful
        if result.returncode != 0:
            print(f"Error running net accounts: {result.stderr}")
            return False
        
        # Extracting the password history value
        output_lines = result.stdout.splitlines()
        for line in output_lines:
            if "Password history requirement" in line:
                # Extracting the number from the line
                value = int(''.join(filter(str.isdigit, line)))
                return value >= min_value
        
        # If the policy was not found in the output
        print("Password history requirement not found in net accounts output.")
        return False

    except Exception as e:
        print(f"Error checking password history policy: {e}")
        return False


def check_dispatcher(benchmark):
    """
    Dispatches the check to the appropriate function based on benchmark type.
    """
    check_functions = {
        "password_history": lambda b: check_enforce_password_history(b.get("min_value", 24)),
    }

    check_func = check_functions.get(benchmark["type"])
    if check_func:
        return check_func(benchmark)
    else:
        print(f"Unknown benchmark type: {benchmark['type']}")
        return False


def run_windows_audit(config, level=None, includes=None, excludes=None):
    """
    Run Windows audit checks based on the specified level, includes, and excludes.
    """
    results = []
    for benchmark in WINDOWS_BENCHMARKS:
        # Filter by level, include, and exclude options
        if (level and benchmark["level"] != level) or \
           (includes and benchmark["id"] not in includes) or \
           (excludes and benchmark["id"] in excludes):
            continue

        # Dispatch to the appropriate check function
        status = check_dispatcher(benchmark)

        results.append({
            "id": benchmark["id"],
            "status": "PASS" if status else "FAIL",
            "description": benchmark["description"]
        })

    return results
