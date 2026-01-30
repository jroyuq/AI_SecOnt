#!/usr/bin/env python3
"""
Main pipeline runner for OntoSec.
Runs the scanner, merge, and global augmentation in sequence.
"""

import subprocess
import sys
import os

def run_command(cmd):
    """Run a command and check for errors."""
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {cmd}")
        print(e.stderr)
        sys.exit(1)

def main():
    # Check if results file exists
    results_file = os.getenv("RESULTS_JSON", "results-scanner-modelscan.json")
    if not os.path.exists(results_file):
        print(f"Error: {results_file} not found. Please place the modelscan results in the current directory.")
        sys.exit(1)

    # Check if CVE feeds exist
    cve_path = os.getenv("CVE_FEEDS_PATH", "CVE-feeds/")
    if not os.path.exists(cve_path):
        print(f"Warning: {cve_path} not found. CVE feeds are required for scanning.")

    # Check other required files
    required_files = [
        os.getenv("ATLAS_PATH", "ATLAS.yaml"),
        os.getenv("BASE_ONTOLOGY", "base_ontology.ttl")
    ]
    for f in required_files:
        if not os.path.exists(f):
            print(f"Error: {f} not found.")
            sys.exit(1)

    print("Starting OntoSec Pipeline...")

    # Step 1: Run Scanner
    print("Step 1: Running Vulnerability Scanner...")
    run_command("python3 vulnerability_scanner.py")

    # Step 2: Merge TTL
    print("Step 2: Merging Local TTL into Global Ontology...")
    run_command("python3 ontology_merger.py")

    # Step 3: Global Scanner
    print("Step 3: Augmenting with ATLAS Techniques...")
    input_file = os.getenv("GLOBAL_TTL", "global_ontology.ttl")
    atlas_file = os.getenv("ATLAS_PATH", "ATLAS.yaml")
    nist_file = os.getenv("NIST_PATH", "NIST.yaml")
    base_onto = os.getenv("BASE_ONTOLOGY", "base_ontology.ttl")
    output_file = os.getenv("GLOBAL_TTL", "global_ontology.ttl")
    run_command(f"python3 global_augmenter.py --input {input_file} --atlas {atlas_file} --nist {nist_file} --base-onto {base_onto} --output {output_file}")

    print("Pipeline completed successfully!")
    print(f"Output: {os.getenv('GLOBAL_TTL', 'global_ontology.ttl')}")

if __name__ == "__main__":
    main()