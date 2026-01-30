#!/usr/bin/env python3
"""
OntoSec Global TTL Augmenter with MITRE ATLAS
Maps Vulnerability descriptions in a local TTL to ATLAS.yaml techniques
and injects technique + mitigation info into a new OntoSec Global TTL.
"""

import argparse
import yaml
import numpy as np
import os
from rdflib import Graph, URIRef, Literal, Namespace, RDF
from rdflib.namespace import XSD, RDFS, OWL
from sentence_transformers import SentenceTransformer, util

# ---------------------------
# Helpers
# ---------------------------
def load_atlas_yaml(atlas_path):
    """Load local ATLAS.yaml and normalize techniques."""
    with open(atlas_path, "r", encoding="utf-8") as f:
        atlas = yaml.safe_load(f)

    normalized = {}
    
    # ATLAS structure: {matrices: [{tactics: [...], techniques: [...]}]}
    if isinstance(atlas, dict):
        # Extract all techniques from all matrices
        matrices = atlas.get("matrices", [])
        if not isinstance(matrices, list):
            matrices = [matrices]
        
        for matrix in matrices:
            # Techniques can be in multiple places in ATLAS structure
            # 1. At matrix level
            techniques_list = matrix.get("techniques", [])
            if not isinstance(techniques_list, list):
                techniques_list = []
            
            # 2. Also check for techniques nested in tactics (subtechniques)
            tactics = matrix.get("tactics", [])
            if isinstance(tactics, list):
                for tactic in tactics:
                    tactic_techniques = tactic.get("techniques", [])
                    if isinstance(tactic_techniques, list):
                        techniques_list.extend(tactic_techniques)
            
            # Process all collected techniques
            for t in techniques_list:
                if not isinstance(t, dict):
                    continue
                if t.get("object-type") != "technique":
                    continue  # skip non-technique entries
                    
                tid = t.get("id")
                name = t.get("name", "").strip()
                desc = t.get("description", "").strip()
                mitigations = t.get("mitigations") or []
                if isinstance(mitigations, dict):
                    mitigations = [mitigations]
                
                if tid:
                    normalized[tid] = {
                        "id": tid,
                        "name": name,
                        "description": desc,
                        "mitigations": mitigations
                    }
    
    print(f"[DEBUG] Loaded {len(normalized)} techniques from ATLAS.yaml")
    return normalized

def load_nist_yaml(nist_path):
    """Load local NIST.yaml and normalize entries (techniques/mitigations/tactics)."""
    with open(nist_path, "r", encoding="utf-8") as f:
        nist = yaml.safe_load(f)

    normalized = {}
    # NIST.yaml in this repo is a list of items; first pass: collect all entries
    if isinstance(nist, list):
        for entry in nist:
            if not isinstance(entry, dict):
                continue
            nid = entry.get("id")
            name = entry.get("name", "").strip()
            desc = entry.get("description", "")
            obj_type = entry.get("object-type", "").lower()
            if nid:
                normalized[nid] = {
                    "id": nid,
                    "name": name,
                    "description": desc.strip() if isinstance(desc, str) else "",
                    "object-type": obj_type,
                    "mitigations": entry.get("mitigations") or [],
                    "tactics": entry.get("tactics", [])
                }
    
    # Second pass: resolve mitigation IDs to full mitigation objects
    for nid, entry in normalized.items():
        resolved_mits = []
        for mit_ref in entry.get("mitigations", []):
            # mit_ref could be a string (ID) or dict; resolve to full object
            if isinstance(mit_ref, str) and mit_ref in normalized:
                # It's an ID, resolve to the full mitigation object
                resolved_mits.append(normalized[mit_ref])
            elif isinstance(mit_ref, dict):
                resolved_mits.append(mit_ref)
            elif isinstance(mit_ref, str):
                # Couldn't resolve; keep as minimal object
                resolved_mits.append({"id": mit_ref, "name": mit_ref, "description": ""})
        entry["mitigations"] = resolved_mits

    print(f"[DEBUG] Loaded {len(normalized)} items from NIST.yaml")
    return normalized

def find_vulnerabilities_local_ns(graph):
    """Find Vulnerability individuals in any namespace."""
    vulns = []
    for s, o in graph.subject_objects(RDF.type):
        if o.split('/')[-1].endswith('Vulnerability') or o.split('#')[-1] == 'Vulnerability':
            # Extract Name and Detail if available
            name = next(graph.objects(s, None), None)
            desc = next(graph.objects(s, None), None)
            vulns.append({"subject": s, "name": None, "description": ""})  # Will populate below
    # More robust: check predicates like :Detail or :Name
    for v in vulns:
        s = v["subject"]
        detail = next(graph.objects(s, None), None)
        if detail:
            v["description"] = str(detail)
        name = next(graph.objects(s, None), None)
        if name:
            v["name"] = str(name)
    return vulns

def qname_local(uri, ns):
    s = str(uri)
    base = str(ns)
    if base in s:
        return s.replace(base, "")
    return s

# ---------------------------
# Main
# ---------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", default=os.getenv("GLOBAL_TTL", "global_ontology.ttl"), help="Input TTL with Vulnerability individuals")
    parser.add_argument("--atlas", "-a", default=os.getenv("ATLAS_PATH", "ATLAS.yaml"), help="Local ATLAS.yaml path")
    parser.add_argument("--nist", default=os.getenv("NIST_PATH", "NIST.yaml"), help="Local NIST.yaml path")
    parser.add_argument("--base-onto", "-b", default=os.getenv("BASE_ONTOLOGY", "base_ontology.ttl"), help="Base OntoSec ontology TTL")
    parser.add_argument("--output", "-o", default=os.getenv("GLOBAL_TTL", "OntoSec_Global-Augmented.ttl"), help="Output TTL file")
    parser.add_argument("--model", "-m", default="all-mpnet-base-v2", help="SentenceTransformer model")
    parser.add_argument("--threshold", "-t", type=float, default=0.35, help="Cosine similarity threshold")
    parser.add_argument("--topk", type=int, default=1, help="Maximum number of ATLAS techniques to attach per vulnerability")
    args = parser.parse_args()

    # Load input TTL
    print("[*] Loading input TTL:", args.input)
    in_g = Graph()
    in_g.parse(args.input, format="turtle")
    print(f"[+] Input graph triples: {len(in_g)}")

    # Load base ontology TTL
    print("[*] Loading base ontology TTL:", args.base_onto)
    base_g = Graph()
    base_g.parse(args.base_onto, format="turtle")
    print(f"[+] Base ontology triples: {len(base_g)}")

    # Unify namespaces: replace any old URIs with the new # namespace
    old_slash_uri = "http://example.org/ontosec/"
    old_ontosec_general_uri = "http://example.org/ontosec#"
    new_uri = "http://example.org/ontosec#"
    new_g = Graph()
    for s, p, o in in_g:
        s_str = str(s)
        new_s = URIRef(s_str.replace(old_slash_uri, new_uri).replace(old_ontosec_general_uri, new_uri))
        p_str = str(p)
        new_p = URIRef(p_str.replace(old_slash_uri, new_uri).replace(old_ontosec_general_uri, new_uri))
        o_str = str(o)
        new_o = URIRef(o_str.replace(old_slash_uri, new_uri).replace(old_ontosec_general_uri, new_uri)) if isinstance(o, URIRef) else o
        new_g.add((new_s, new_p, new_o))
    in_g = new_g
    print(f"[+] Unified namespaces in input graph")

    # Use the unified namespace
    ns_uri = "http://example.org/ontosec#"
    ONTOSEC = Namespace(ns_uri)
    print(f"[+] Using OntoSec namespace: {ONTOSEC}")

    # Find vulnerabilities in input graph
    vulns = []
    for s, o in in_g.subject_objects(RDF.type):
        if o.split('/')[-1].endswith('Vulnerability') or o.split('#')[-1] == 'Vulnerability':
            # extract description and name if present
            desc = ""
            name = ""

            # Preferred predicates in OntoSec namespace
            for p in [ONTOSEC.Description, URIRef(str(ONTOSEC)+"Detail")]:
                for o_desc in in_g.objects(s, p):
                    desc = str(o_desc)
                    break
                if desc:
                    break

            # If not found, search any predicate whose local name matches common fields
            if not desc:
                for p, o_desc in in_g.predicate_objects(s):
                    local = str(p).split('/')[-1].split('#')[-1]
                    if local.lower() in ("detail", "description", "hascvedescription", "hascvedesc"):
                        desc = str(o_desc)
                        break

            # Fallback: first literal object value
            if not desc:
                for o_desc in in_g.objects(s):
                    if hasattr(o_desc, 'toPython') or isinstance(o_desc, Literal):
                        desc = str(o_desc)
                        break

            # Name: try OntoSec Name then common name/title predicates
            for p in [ONTOSEC.Name, URIRef(str(ONTOSEC)+"Name")]:
                for o_name in in_g.objects(s, p):
                    name = str(o_name)
                    break
                if name:
                    break
            if not name:
                for p, o_name in in_g.predicate_objects(s):
                    local = str(p).split('/')[-1].split('#')[-1]
                    if local.lower() in ("name", "title"):
                        name = str(o_name)
                        break

            vulns.append({"subject": s, "name": name, "description": desc})
    print(f"[+] Found {len(vulns)} Vulnerability individuals.")

    if not vulns:
        print("[-] No vulnerabilities found. Exiting.")
        return

    # Load ATLAS.yaml
    print("[*] Loading ATLAS.yaml ...")
    atlas = load_atlas_yaml(args.atlas)
    atlas_items = list(atlas.values())
    print(f"[+] Loaded {len(atlas_items)} ATLAS techniques.")

    # Load NIST.yaml (optional)
    nist_items = {}
    nist_texts = []
    nist_embeddings = None
    if args.nist and os.path.exists(args.nist):
        print("[*] Loading NIST.yaml ...")
        nist = load_nist_yaml(args.nist)
        # Keep only techniques for matching but retain mitigations for later
        nist_items = [v for v in nist.values() if v.get("object-type") == "technique"]
        print(f"[+] Loaded {len(nist_items)} NIST techniques.")
        nist_texts = [t.get("name","") + " - " + t.get("description","") for t in nist_items]
    else:
        print("[-] NIST.yaml not found or not provided; skipping NIST augmentation.")

    # Prepare texts for ATLAS embeddings
    atlas_texts = [t.get("name","") + " - " + t.get("description","") for t in atlas_items]

    # Load embedding model
    print(f"[*] Loading embedding model `{args.model}` ...")
    embed_model = SentenceTransformer(args.model)

    print("[*] Encoding ATLAS techniques ...")
    atlas_embeddings = embed_model.encode(atlas_texts, convert_to_tensor=True, show_progress_bar=True)

    # Encode NIST techniques if present
    if nist_texts:
        print("[*] Encoding NIST techniques ...")
        nist_embeddings = embed_model.encode(nist_texts, convert_to_tensor=True, show_progress_bar=True)

    # Merge base + input graph
    out_g = base_g + in_g
    out_g.bind("ontosec", ns_uri)

    # Detect a local namespace to declare the local object property (:have)
    local_ns_uri = None
    for prefix, ns in in_g.namespaces():
        # prefer the default or any namespace that looks like a local OntoSec
        if prefix == "" or "Local" in str(ns) or "Local-ModelScan" in str(ns):
            local_ns_uri = str(ns)
            break
    # Fallback: derive from the first vulnerability subject if available
    if not local_ns_uri and vulns:
        s0 = str(vulns[0]["subject"])
        if "#" in s0:
            local_ns_uri = s0.split("#")[0] + "#"
        else:
            local_ns_uri = s0.rsplit("/", 1)[0] + "/"
    if not local_ns_uri:
        local_ns_uri = "http://example.org/local#"

    HAVE = URIRef(str(local_ns_uri) + "have")
    # Declare the local property as an OWL ObjectProperty so it appears in the output
    out_g.add((HAVE, RDF.type, OWL.ObjectProperty))

    # Ontology predicates & classes
    VULN = ONTOSEC.Vulnerability
    MIT = ONTOSEC.Mitigation
    TECH = ONTOSEC.Technique
    NAME = ONTOSEC.Name
    DESC = ONTOSEC.Description
    ATTREF = URIRef(str(ONTOSEC) + "ATTCK-reference-id")
    NISTREF = URIRef(str(ONTOSEC) + "NIST-reference-id")
    HASNIST = ONTOSEC.hasNISTTechnique
    ISMIT = ONTOSEC.isMitigatedBy
    HASTECH = ONTOSEC.hasTechnique
    MATCH_SCORE = ONTOSEC.matchScore
    MATCH_RANK = ONTOSEC.matchRank

    # Add class declarations
    out_g.add((TECH, RDF.type, OWL.Class))
    out_g.add((VULN, RDF.type, OWL.Class))
    out_g.add((MIT, RDF.type, OWL.Class))

    # Process each vulnerability
    for idx, v in enumerate(vulns, start=1):
        desc = v["description"] or v["name"]
        if not desc.strip():
            continue
        print(f"\n[*] Processing Vulnerability {idx}: {v['name']}")

        v_emb = embed_model.encode(desc, convert_to_tensor=True)
        cos_scores = util.cos_sim(v_emb, atlas_embeddings)[0].cpu().numpy()

        # Sort atlas techniques by descending similarity and keep those above threshold
        ranked_idx = list(reversed(np.argsort(cos_scores)))
        matches = []
        for ridx in ranked_idx:
            score = float(cos_scores[int(ridx)])
            if score < args.threshold:
                break
            matches.append((int(ridx), score))
            if len(matches) >= args.topk:
                break

        subj_v = v["subject"]

        # Ensure Name and Description present on vulnerability
        if not list(out_g.objects(subj_v, NAME)):
            out_g.add((subj_v, NAME, Literal(v.get("name",""), datatype=XSD.string)))
        if v.get("description"):
            out_g.add((subj_v, DESC, Literal(v.get("description",""), datatype=XSD.string)))

        if not matches:
            # fallback: still attach top-1 even if below threshold (optional behavior)
            best_idx = int(np.argmax(cos_scores))
            best_score = float(cos_scores[best_idx])
            matches = [(best_idx, best_score)]

        print(f"  -> Found {len(matches)} ATLAS match(es) (threshold {args.threshold})")

        for rank, (m_idx, m_score) in enumerate(matches, start=1):
            matched = atlas_items[m_idx]
            print(f"    {rank}. {matched['id']} - {matched['name']} (score {m_score:.3f})")
            # Print a short description preview for clarity
            tech_desc = matched.get('description','').strip()
            if tech_desc:
                preview = tech_desc if len(tech_desc) <= 240 else tech_desc[:237] + '...'
                print(f"       description: {preview}")
            # Print mitigation summary (if any)
            mitig_list = matched.get('mitigations') or []
            if mitig_list:
                print(f"       mitigations: {len(mitig_list)} item(s)")

            # Add ATT&CK reference (first match only)
            if rank == 1:
                out_g.add((subj_v, ATTREF, Literal(matched["id"], datatype=XSD.string)))

            # Create Technique individual (one per ATLAS technique)
            tech_node = URIRef(str(ONTOSEC) + f"Technique_{matched['id']}")
            # Only add technique triples if not already present
            if not list(out_g.triples((tech_node, None, None))):
                out_g.add((tech_node, RDF.type, TECH))
                out_g.add((tech_node, NAME, Literal(matched.get("name", ""), datatype=XSD.string)))
                out_g.add((tech_node, DESC, Literal(matched.get("description", ""), datatype=XSD.string)))
                out_g.add((tech_node, ATTREF, Literal(matched["id"], datatype=XSD.string)))
            # Add provenance: match score and rank as data properties on technique
            out_g.add((tech_node, MATCH_SCORE, Literal(m_score, datatype=XSD.float)))
            out_g.add((tech_node, MATCH_RANK, Literal(rank, datatype=XSD.int)))
            # Link vulnerability to technique
            out_g.add((subj_v, HASTECH, tech_node))
            # Also assert local object property linking vulnerability to technique (e.g., :have)
            out_g.add((subj_v, HAVE, tech_node))

            # Create Mitigation node for technique
            mit_node = URIRef(str(ONTOSEC) + f"Mitigation_{matched['id']}_{rank}")
            out_g.add((mit_node, RDF.type, MIT))
            out_g.add((mit_node, NAME, Literal(matched.get("name",""), datatype=XSD.string)))
            out_g.add((mit_node, DESC, Literal(matched.get("description",""), datatype=XSD.string)))
            out_g.add((mit_node, ATTREF, Literal(matched["id"], datatype=XSD.string)))
            out_g.add((subj_v, ISMIT, mit_node))
            # Also assert local property linking vulnerability to mitigation
            out_g.add((subj_v, HAVE, mit_node))

            # Add additional mitigations if available
            for m_i, mit in enumerate(matched.get("mitigations", []) or []):
                if isinstance(mit, dict):
                    m_name = mit.get("name") or mit.get("title") or ""
                    m_desc = mit.get("description") or mit.get("details") or ""
                    m_id = mit.get("id") or ""
                else:
                    m_name = str(mit)
                    m_desc = ""
                    m_id = ""
                node = URIRef(str(ONTOSEC) + f"Mitigation_{matched['id']}_{rank}_{m_i}")
                out_g.add((node, RDF.type, MIT))
                if m_name:
                    out_g.add((node, NAME, Literal(m_name, datatype=XSD.string)))
                if m_desc:
                    out_g.add((node, DESC, Literal(m_desc, datatype=XSD.string)))
                if m_id:
                    out_g.add((node, ATTREF, Literal(m_id, datatype=XSD.string)))
                out_g.add((subj_v, ISMIT, node))

        # --- NIST matching (if NIST data is present) ---
        if nist_embeddings is not None and nist_texts:
            cos_scores_nist = util.cos_sim(v_emb, nist_embeddings)[0].cpu().numpy()
            ranked_nidx = list(reversed(np.argsort(cos_scores_nist)))
            n_matches = []
            for ridx in ranked_nidx:
                score = float(cos_scores_nist[int(ridx)])
                if score < args.threshold:
                    break
                n_matches.append((int(ridx), score))
                if len(n_matches) >= args.topk:
                    break

            if not n_matches:
                best_nidx = int(np.argmax(cos_scores_nist))
                best_nscore = float(cos_scores_nist[best_nidx])
                n_matches = [(best_nidx, best_nscore)]

            print(f"  -> Found {len(n_matches)} NIST match(es) (threshold {args.threshold})")
            for n_rank, (n_idx, n_score) in enumerate(n_matches, start=1):
                nmatched = nist_items[n_idx]
                print(f"    {n_rank}. {nmatched['id']} - {nmatched['name']} (score {n_score:.3f})")
                n_desc = nmatched.get('description','').strip()
                if n_desc:
                    preview = n_desc if len(n_desc) <= 240 else n_desc[:237] + '...'
                    print(f"       description: {preview}")

                # Add NIST reference (first match only)
                if n_rank == 1:
                    out_g.add((subj_v, NISTREF, Literal(nmatched['id'], datatype=XSD.string)))

                # Create NIST Technique individual
                ntech_node = URIRef(str(ONTOSEC) + f"Technique_NIST_{nmatched['id']}")
                if not list(out_g.triples((ntech_node, None, None))):
                    out_g.add((ntech_node, RDF.type, TECH))
                    out_g.add((ntech_node, NAME, Literal(nmatched.get('name',''), datatype=XSD.string)))
                    out_g.add((ntech_node, DESC, Literal(nmatched.get('description',''), datatype=XSD.string)))
                    out_g.add((ntech_node, NISTREF, Literal(nmatched['id'], datatype=XSD.string)))

                # Add provenance
                out_g.add((ntech_node, MATCH_SCORE, Literal(n_score, datatype=XSD.float)))
                out_g.add((ntech_node, MATCH_RANK, Literal(n_rank, datatype=XSD.int)))
                # Link vulnerability to NIST technique
                out_g.add((subj_v, HASNIST, ntech_node))
                out_g.add((subj_v, HAVE, ntech_node))

                # If the NIST technique lists mitigations, add them
                for m_i, mit in enumerate(nmatched.get('mitigations', []) or []):
                    if isinstance(mit, dict):
                        m_name = mit.get('name') or mit.get('title') or ''
                        m_desc = mit.get('description') or mit.get('details') or ''
                        m_id = mit.get('id') or ''
                    else:
                        m_name = str(mit)
                        m_desc = ''
                        m_id = ''
                    node = URIRef(str(ONTOSEC) + f"Mitigation_NIST_{nmatched['id']}_{n_rank}_{m_i}")
                    out_g.add((node, RDF.type, MIT))
                    if m_name:
                        out_g.add((node, NAME, Literal(m_name, datatype=XSD.string)))
                    if m_desc:
                        out_g.add((node, DESC, Literal(m_desc, datatype=XSD.string)))
                    if m_id:
                        out_g.add((node, NISTREF, Literal(m_id, datatype=XSD.string)))
                    out_g.add((subj_v, ISMIT, node))
                    out_g.add((subj_v, HAVE, node))

    # Serialize output
    out_g.serialize(destination=args.output, format="turtle")
    print(f"\n[+] Wrote augmented ontology to: {args.output} (total triples: {len(out_g)})")


if __name__ == "__main__":
    main()

