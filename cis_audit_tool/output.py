import csv
import json
import sys
def generate_output(results, output_format="text"):
    """Generate output in the specified format."""
    if output_format == "text":
        for result in results:
            print(f"{result['id']}: {result['status']} - {result['description']}")
    elif output_format == "json":
        print(json.dumps(results, indent=2))
    elif output_format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    elif output_format == "psv":
        writer = csv.DictWriter(sys.stdout, fieldnames=results[0].keys(), delimiter="|")
        writer.writeheader()
        writer.writerows(results)
    elif output_format == "tsv":
        writer = csv.DictWriter(sys.stdout, fieldnames=results[0].keys(), delimiter="\t")
        writer.writeheader()
        writer.writerows(results)