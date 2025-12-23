#!/usr/bin/env python3
"""
Cleanup script for OntoSec Pipeline.
Deletes all generated result files to allow fresh re-initialization.
"""

import os
import sys

def cleanup_results():
    """Delete all generated result files."""

    # Files to delete (generated outputs)
    files_to_delete = [
        "local_ontology.ttl",
        "global_ontology.ttl"
    ]

    # Files to keep (base files)
    keep_files = [
        "base_ontology.ttl",  # Base ontology - part of start pack
        "ATLAS.yaml",         # ATLAS data
        "results-scanner-modelscan.json"  # User input
    ]

    print("🧹 OntoSec Pipeline Cleanup")
    print("=" * 30)

    deleted_count = 0
    for filename in files_to_delete:
        if os.path.exists(filename):
            try:
                os.remove(filename)
                print(f"✅ Deleted: {filename}")
                deleted_count += 1
            except OSError as e:
                print(f"❌ Error deleting {filename}: {e}")
        else:
            print(f"ℹ️  Not found: {filename}")

    print(f"\n📊 Summary: {deleted_count} files deleted")

    # Verify kept files
    print("\n📁 Files preserved:")
    for filename in keep_files:
        if os.path.exists(filename):
            print(f"✅ {filename}")
        else:
            print(f"⚠️  {filename} (not found)")

    print("\n🎯 Ready for fresh pipeline run!")
    print("Run 'python3 main.py' to start again.")

def main():
    """Main function with confirmation."""
    print("This will delete all generated result files.")
    print("Your modelscan results and base files will be preserved.")
    print()

    # Simple confirmation
    response = input("Continue? (y/N): ").strip().lower()
    if response in ['y', 'yes']:
        cleanup_results()
    else:
        print("Cleanup cancelled.")
        sys.exit(0)

if __name__ == "__main__":
    main()