#!/usr/bin/env python3
"""
Merge local_ontology.ttl into global_ontology.ttl
Only merges individuals of the Issue class as individuals of the Vulnerability class.
"""

import os
from rdflib import Graph, RDF, Namespace

# Files
GENERAL_TTL = os.getenv("GLOBAL_TTL", "global_ontology.ttl")
LOCAL_TTL = os.getenv("LOCAL_TTL", "local_ontology.ttl")

# Namespace
ontosec = Namespace("http://example.org/ontosec#")

# Load the general graph if it exists
g_general = Graph()
if os.path.exists(GENERAL_TTL):
    g_general.parse(GENERAL_TTL, format="turtle")

# Load the local graph
g_local = Graph()
g_local.parse(LOCAL_TTL, format="turtle")

# Find all individuals of Issue and add them as Vulnerability
for s in g_local.subjects(RDF.type, ontosec.Issue):
    # Remove the Issue type if present in general
    if (s, RDF.type, ontosec.Issue) in g_general:
        g_general.remove((s, RDF.type, ontosec.Issue))
    # Add as Vulnerability
    g_general.add((s, RDF.type, ontosec.Vulnerability))
    # Add all other triples for this individual
    for p, o in g_local.predicate_objects(s):
        if not (p == RDF.type and o == ontosec.Issue):
            g_general.add((s, p, o))

# Serialize back to general file
g_general.serialize(GENERAL_TTL, format="turtle")

print(f"Merged Issue individuals as Vulnerability into {GENERAL_TTL}")