#!/usr/bin/env python3
"""
Merge local_ontology.ttl into global_ontology.ttl
Keeps individuals as Issue class (subclass of Vulnerability).
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

# Ensure Issue class definition exists in general graph
if (ontosec.Issue, RDF.type, None) not in g_general:
    from rdflib.namespace import RDFS, OWL
    from rdflib import Literal
    g_general.bind("ontosec", ontosec)
    g_general.add((ontosec.Issue, RDF.type, OWL.Class))
    g_general.add((ontosec.Issue, RDFS.subClassOf, ontosec.Vulnerability))
    g_general.add((ontosec.Issue, RDFS.label, Literal("Issue")))

# Find all individuals of Issue and add them as Issue (preserving class hierarchy)
for s in g_local.subjects(RDF.type, ontosec.Issue):
    # Add as Issue (which is a subclass of Vulnerability)
    g_general.add((s, RDF.type, ontosec.Issue))
    # Add all other triples for this individual
    for p, o in g_local.predicate_objects(s):
        if not (p == RDF.type and o == ontosec.Issue):
            g_general.add((s, p, o))

# Serialize back to general file
g_general.serialize(GENERAL_TTL, format="turtle")

print(f"Merged Issue individuals (preserving Issue class) into {GENERAL_TTL}")