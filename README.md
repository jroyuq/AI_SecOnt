# OntoSec Pipeline

A comprehensive pipeline for scanning machine learning models for vulnerabilities, merging them into an ontology, and augmenting with MITRE ATLAS techniques.

## Quick Start for New Users

1. **Get your modelscan results**: Run modelscan on your ML models and save the JSON output as `results-scanner-modelscan.json`
2. **Add your results**: Copy your `results-scanner-modelscan.json` file to this directory (see `example-results/` for the expected format)
3. **Run the pipeline**:
   ```bash
   python3 main.py
   ```

That's it! The pipeline will process your results and generate an augmented ontology.

## Resetting for New Scans

To clean up generated files and start fresh with new modelscan results:

```bash
python3 cleanup.py
```

This will delete all output files while preserving your input data and base files.

## File Structure

- `example-results/`: Contains an example modelscan results file showing the expected JSON format
- `CVE-feeds/`: Pre-loaded CVE database feeds for vulnerability matching
- `*.py`: Pipeline scripts (main.py is the entry point)
- `*.ttl`: Ontology files (base_ontology.ttl is required, others are generated)

## Prerequisites

- Python 3.8+
- Modelscan results JSON file (see `example-results/` for expected format)
- CVE feeds (included in `CVE-feeds/` directory)

## Installation

```bash
pip install -r requirements.txt
```

## What the Pipeline Does

1. **Scans vulnerabilities**: Matches your modelscan issues to CVE database using semantic similarity
2. **Merges ontologies**: Safely combines local findings into a general vulnerability ontology
3. **Augments with ATLAS**: Links vulnerabilities to MITRE ATLAS techniques and recommended mitigations

## Output

The final result is `global_ontology.ttl` containing:
- Your vulnerabilities linked to specific CVEs
- Associated ATLAS attack techniques
- Recommended mitigation strategies
- All properly structured with no duplicate classes

## Configuration

Customize paths in `.env` file if needed:
- `RESULTS_JSON`: Your modelscan results file (default: results-scanner-modelscan.json)
- `GLOBAL_TTL`: Output file name (default: global_ontology.ttl)

## Advanced Usage

### Jenkins CI/CD Integration
For organizations wanting to integrate ML vulnerability scanning into their CI/CD pipelines:

1. Set up a Jenkins job with this repository
2. The `Jenkinsfile` provides automated execution with artifact archiving
3. Results are automatically saved as build artifacts

### Manual Usage
For individual users, simply run:
```bash
python3 main.py
```

### Custom CVE Feeds
Update the `CVE-feeds/` directory with the latest NVD feeds for more comprehensive scanning.

### ATLAS Customization
Modify `ATLAS.yaml` to include custom techniques or update with latest MITRE ATLAS data.

## License

[Add your license here]