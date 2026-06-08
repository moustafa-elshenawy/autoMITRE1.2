"""
attack_hierarchical
===================
Hierarchical deep-learning ATT&CK mapper:

    dataset.py   data pipeline + TRAM/BRON-style mock corpus + cyber tokenizer
    model.py     MultiLabelHierarchicalClassifier (twin heads) + HierarchicalConsistencyLoss
    reranker.py  Bi-Encoder + Cross-Encoder semantic verification gate
    metrics.py   Macro-F1 / macro Average-Precision / PR curves
    train.py     MPS-accelerated training loop with mixed precision
    predict.py   raw text -> classifier -> re-ranker -> thresholded JSON

Public surface:

    from ml.attack_hierarchical.predict import HierarchicalPredictor
    from ml.attack_hierarchical.taxonomy import load_taxonomy
"""
from .taxonomy import Taxonomy, load_taxonomy
from .model import MultiLabelHierarchicalClassifier, HierarchicalConsistencyLoss
from .reranker import SemanticVerifier

__all__ = [
    "Taxonomy",
    "load_taxonomy",
    "MultiLabelHierarchicalClassifier",
    "HierarchicalConsistencyLoss",
    "SemanticVerifier",
]
