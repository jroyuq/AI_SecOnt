# AI SecOnto

A comprehensive pipeline for scanning machine learning models for vulnerabilities, merging them into an ontology, and augmenting with MITRE ATLAS and NIST AI security techniques.

**Latest Updates**: Ontology structure now includes `Issue` as a subclass of `Vulnerability` for better semantic organization.

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
- `CVE-feeds/`: Directory for CVE database feeds (download required, see below)
- `ATLAS.yaml`: MITRE ATLAS AI security techniques and mitigations
- `NIST.yaml`: NIST AI security techniques and mitigations
- `*.py`: Pipeline scripts (main.py is the entry point)
- `*.ttl`: Ontology files (base_ontology.ttl is required, others are generated)

## CVE Feeds (Required – Not Included in Repository)

⚠️ CVE feeds are NOT stored in this repository due to their large size and frequent updates.

You must download them manually or via CI (recommended).

### Official Source (NVD – NIST)

Download CVE JSON feeds from the official NVD website:

https://nvd.nist.gov/vuln/data-feeds

Direct feed format used by this pipeline:

```bash
nvdcve-2.0-YYYY.json.gz
```

### How CVEs Are Processed

The pipeline performs the following steps for CVE matching:

1. **Loading**: Decompresses and loads CVE data from `.json.gz` files on-the-fly (no persistent decompression)
2. **Filtering**: Pre-filters CVEs using keywords: `["python", "pickle", "pytorch"]` to focus on relevant AI/ML security issues
3. **Semantic Matching**: Uses AI embeddings to semantically match vulnerability descriptions with CVE descriptions
4. **Association**: Links issues to CVEs when similarity score ≥ 0.50

**Note**: Files are decompressed in memory during each run - the compressed `.gz` files remain unchanged on disk.

### Supported years typically include:

2020 – current year

### Expected Directory Structure

After downloading, your project should look like this:

```bash
OntoSec/
├── CVE-feeds/
│   ├── nvdcve-2.0-2020.json.gz
│   ├── nvdcve-2.0-2021.json.gz
│   ├── nvdcve-2.0-2022.json.gz
│   ├── nvdcve-2.0-2023.json.gz
│   ├── nvdcve-2.0-2024.json.gz
│   └── nvdcve-2.0-2025.json.gz
├── results-scanner-modelscan.json
├── main.py
├── requirements.txt
└── ...
```

The pipeline expects this exact directory name:

```bash
CVE-feeds/
```

## Prerequisites

- Python 3.8+
- Modelscan results JSON file (see `example-results/` for expected format)
- CVE feeds (included in `CVE-feeds/` directory)

## Installation

```bash
pip install -r requirements.txt
```

## What the Pipeline Does

1. **Scans vulnerabilities**: Matches your modelscan issues to CVE database using semantic similarity with AI embeddings
2. **Merges ontologies**: Safely combines local findings into a general vulnerability ontology
3. **Augments with ATLAS**: Links vulnerabilities to MITRE ATLAS techniques and recommended mitigations
4. **Augments with NIST**: Links vulnerabilities to NIST AI security techniques and mitigations

## AI Model Used

The pipeline uses **SentenceTransformer `all-mpnet-base-v2`** for semantic text matching:
- Converts vulnerability descriptions into 768-dimensional embeddings
- Performs cosine similarity calculations for intelligent matching
- Enables semantic understanding beyond simple keyword matching

## Output

The final result is `global_ontology.ttl` containing:
- Your vulnerabilities linked to specific CVEs
- Associated ATLAS attack techniques with detailed relationships
- Associated NIST AI security techniques with mitigations
- Recommended mitigation strategies
- All properly structured with detailed object properties

### Ontology Relationships

The ontology uses detailed object properties for precise semantic relationships:

- `Mitigates`: Links mitigations to what they mitigate
- `isMitigatedBy`: Links vulnerabilities to their mitigations
- `isExploitedBy`: Links vulnerabilities to exploiting techniques
- `hasTechnique`: Links issues to associated attack techniques

#### Class Hierarchy

The ontology follows this class structure:
- `Vulnerability` (top-level class)
  - `Issue` (subclass of Vulnerability)
    - `Issue_1`, `Issue_2`, etc. (instances of Issue)

Individual issues are instances of the `Issue` class, which is a subclass of `Vulnerability`.

## Querying the Ontology

Use SPARQL queries to extract insights from your security ontology:

### Find All Issues and Their Types
```sparql
PREFIX ontosec: <http://example.org/ontosec#>

SELECT ?issue ?type
WHERE {
  ?issue a ontosec:Issue .
  ?issue a ?type .
  FILTER(?type != ontosec:Issue)  # Show additional types
}
```

### Find All Mitigations for a Specific Issue
```sparql
PREFIX ontosec: <http://example.org/ontosec#>

SELECT ?mitigation ?name ?description ?reference
WHERE {
  ontosec:Issue_1 ontosec:isMitigatedBy ?mitigation .
  ?mitigation ontosec:Name ?name .
  OPTIONAL { ?mitigation ontosec:Description ?description }
  OPTIONAL {
    ?mitigation ontosec:ATTCK-reference-id ?reference
  }
  OPTIONAL {
    ?mitigation ontosec:NIST-reference-id ?reference
  }
}
```

### Find All Mitigations Across All Issues
```sparql
PREFIX ontosec: <http://example.org/ontosec#>

SELECT ?issue ?mitigation ?name ?description
WHERE {
  ?issue ontosec:isMitigatedBy ?mitigation .
  ?mitigation ontosec:Name ?name .
  OPTIONAL { ?mitigation ontosec:Description ?description }
}
```

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

### NIST Customization
Modify `NIST.yaml` to include additional AI security techniques or update with latest NIST guidelines.
