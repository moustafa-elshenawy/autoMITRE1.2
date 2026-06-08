"""
threat_pipeline.build_index
============================
One-off / idempotent CLI to (re)populate the ChromaDB vector store from the
shipped MITRE ATT&CK corpus (``data/mitre_attack.json``).

Usage (from the backend root, inside the venv):

    python -m core.threat_pipeline.build_index            # build if empty
    python -m core.threat_pipeline.build_index --force    # wipe & rebuild
"""
import argparse
import logging

from .retriever import retriever


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Build the MITRE ATT&CK vector index.")
    parser.add_argument("--force", action="store_true", help="Wipe and rebuild the index.")
    args = parser.parse_args()

    if not args.force and retriever.is_populated():
        print("Index already populated. Use --force to rebuild.")
        return

    count = retriever.build_index(force=args.force)
    print(f"Done. Indexed {count} MITRE techniques.")


if __name__ == "__main__":
    main()
