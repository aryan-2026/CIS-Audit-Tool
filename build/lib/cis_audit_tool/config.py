import json
import yaml

def load_config(config_file):
    """Load configuration from a file."""
    if not config_file:
        return {}

    try:
        with open(config_file, "r") as f:
            if config_file.endswith(".json"):
                return json.load(f)
            elif config_file.endswith(".yaml") or config_file.endswith(".yml"):
                return yaml.safe_load(f)
            else:
                raise ValueError("Unsupported config file format")
    except Exception as e:
        print(f"Error loading config file: {e}")
        return {}