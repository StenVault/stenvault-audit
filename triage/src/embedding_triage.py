"""
Layer 2: Embedding similarity triage using Ollama's nomic-embed-text.
Compares findings against documented design decisions to reject known-good patterns.
"""

import os
import json
import requests
from pathlib import Path

import chromadb

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434")
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "nomic-embed-text")
DESIGN_DOCS_DIR = Path(os.environ.get("DESIGN_DOCS_DIR", "/design-docs"))
TRIAGE_DB_DIR = Path(os.environ.get("TRIAGE_DB_DIR", "/triage-db"))
REJECTION_THRESHOLD = float(os.environ.get("REJECTION_THRESHOLD", "0.35"))


def get_embedding(text: str) -> list[float]:
    """Get embedding vector from Ollama's nomic-embed-text model."""
    response = requests.post(
        f"{OLLAMA_URL}/api/embeddings",
        json={
            "model": EMBEDDING_MODEL,
            "prompt": text,
        },
        timeout=60,
    )
    response.raise_for_status()
    return response.json()["embedding"]


def init_design_doc_db() -> chromadb.Collection:
    """
    Index design documents into ChromaDB for similarity search.
    Splits documents into sections for granular matching.
    """
    client = chromadb.PersistentClient(path=str(TRIAGE_DB_DIR))

    # Recreate collection for fresh index
    try:
        client.delete_collection("design_decisions")
    except Exception:
        pass

    collection = client.create_collection(
        name="design_decisions",
        metadata={"hnsw:space": "cosine"},
    )

    documents = []
    ids = []
    embeddings = []
    doc_id = 0

    for doc_file in sorted(DESIGN_DOCS_DIR.glob("*.md")):
        print(f"  Indexing: {doc_file.name}")
        content = doc_file.read_text(encoding="utf-8", errors="replace")

        # Split by sections (## headers) or double newlines
        sections = []
        current = []
        for line in content.split("\n"):
            if line.startswith("## ") and current:
                sections.append("\n".join(current))
                current = [line]
            else:
                current.append(line)
        if current:
            sections.append("\n".join(current))

        for section in sections:
            section = section.strip()
            # Skip very short sections (headers-only, empty)
            if len(section) < 80:
                continue

            try:
                embedding = get_embedding(section[:2000])  # Truncate for embedding
                documents.append(section[:2000])
                embeddings.append(embedding)
                ids.append(f"doc_{doc_id}")
                doc_id += 1
            except Exception as e:
                print(f"  Warning: Failed to embed section: {e}")
                continue

    if documents:
        collection.add(
            documents=documents,
            embeddings=embeddings,
            ids=ids,
        )
        print(f"  Indexed {len(documents)} design doc sections into ChromaDB")
    else:
        print("  Warning: No design doc sections indexed")

    return collection


def embedding_triage(findings: list[dict]) -> list[dict]:
    """
    For each finding that passed Layer 1, check if it matches a documented
    design decision (which means it's likely a false positive).
    """
    client = chromadb.PersistentClient(path=str(TRIAGE_DB_DIR))

    try:
        collection = client.get_collection("design_decisions")
    except Exception:
        print("  Warning: Design doc DB not initialized. Run init first.")
        print("  Skipping embedding triage.")
        return findings

    count = collection.count()
    if count == 0:
        print("  Warning: Design doc DB is empty. Skipping embedding triage.")
        return findings

    for f in findings:
        if f.get("triage_status") != "passed_layer1":
            continue

        # Build query from finding
        checklist = f.get("checklist_item", "")
        finding_text = f.get("finding", "")
        query = f"{checklist}: {finding_text}"

        try:
            query_embedding = get_embedding(query)
            results = collection.query(
                query_embeddings=[query_embedding],
                n_results=3,
            )

            if results["distances"] and results["distances"][0]:
                top_distance = results["distances"][0][0]
                top_doc = results["documents"][0][0] if results["documents"][0] else ""

                f["design_doc_distance"] = round(top_distance, 4)
                f["matched_design_doc"] = top_doc[:200]

                if top_distance < REJECTION_THRESHOLD:
                    f["triage_status"] = "rejected_by_ml"
                    f["triage_reason"] = "matches_design_decision"
                    f["triage_confidence"] = round(1 - top_distance, 4)
                else:
                    f["triage_status"] = "validated"
                    f["triage_confidence"] = round(top_distance, 4)
            else:
                f["triage_status"] = "validated"
                f["triage_confidence"] = 1.0

        except Exception as e:
            print(f"  Warning: Embedding triage failed for {checklist}: {e}")
            f["triage_status"] = "validated"
            f["triage_confidence"] = 0.5

    return findings
