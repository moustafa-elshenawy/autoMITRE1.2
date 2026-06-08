"""
attack_hierarchical.model
=========================
The neural architecture.

  * ``MultiLabelHierarchicalClassifier`` — a pre-trained transformer core with
    twin parallel heads: Head A (Tactics) and Head B (Techniques), both
    multi-label. Uses masked mean-pooling so it works for BERT *and* RoBERTa
    (SecureBERT) backbones without relying on a pooler.
  * ``HierarchicalConsistencyLoss`` — BCE-with-logits on both heads PLUS two
    differentiable hierarchy penalties:
        (1) a technique's probability may not exceed its parent tactic's
            probability  (Technique -> Tactic),
        (2) a sub-technique's probability may not exceed its base technique's
            probability  (Sub-technique -> Technique).
    Both encode "don't fire a child without its parent".
"""
from __future__ import annotations

import logging
from typing import Dict, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoConfig, AutoModel

from . import config

log = logging.getLogger("attack_hierarchical.model")


def load_backbone(name: Optional[str] = None) -> Tuple[nn.Module, str, int]:
    """Load the transformer core, falling back if the primary is unavailable.

    Returns (model, resolved_name, hidden_size).
    """
    name = name or config.TRANSFORMER_MODEL
    try:
        cfg = AutoConfig.from_pretrained(name)
        model = AutoModel.from_pretrained(name)
        log.info("Backbone loaded: %s (hidden=%d)", name, cfg.hidden_size)
        return model, name, cfg.hidden_size
    except Exception as e:  # noqa: BLE001
        log.warning("Backbone '%s' unavailable (%s); falling back to '%s'.",
                    name, e, config.TRANSFORMER_FALLBACK)
        cfg = AutoConfig.from_pretrained(config.TRANSFORMER_FALLBACK)
        model = AutoModel.from_pretrained(config.TRANSFORMER_FALLBACK)
        return model, config.TRANSFORMER_FALLBACK, cfg.hidden_size


class MultiLabelHierarchicalClassifier(nn.Module):
    """Transformer encoder + twin multi-label heads (Tactics, Techniques)."""

    def __init__(self, num_tactics: int, num_techniques: int,
                 backbone_name: Optional[str] = None, dropout: float = config.DROPOUT):
        super().__init__()
        self.backbone, self.backbone_name, hidden = load_backbone(backbone_name)
        self.num_tactics = num_tactics
        self.num_techniques = num_techniques

        self.dropout = nn.Dropout(dropout)
        # Head A — Tactics (coarse). Head B — Techniques (fine, incl. sub-techs).
        self.tactic_head = nn.Linear(hidden, num_tactics)
        self.technique_head = nn.Linear(hidden, num_techniques)
        self._init_heads()

    def _init_heads(self) -> None:
        for head in (self.tactic_head, self.technique_head):
            nn.init.xavier_uniform_(head.weight)
            nn.init.zeros_(head.bias)

    @staticmethod
    def _mean_pool(last_hidden: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        """Attention-masked mean pooling over the token dimension."""
        mask = attention_mask.unsqueeze(-1).type_as(last_hidden)  # [B, L, 1]
        summed = (last_hidden * mask).sum(dim=1)
        counts = mask.sum(dim=1).clamp(min=1e-9)
        return summed / counts

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor
                ) -> Dict[str, torch.Tensor]:
        out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
        pooled = self._mean_pool(out.last_hidden_state, attention_mask)
        pooled = self.dropout(pooled)
        return {
            "tactic_logits": self.tactic_head(pooled),
            "technique_logits": self.technique_head(pooled),
        }


class HierarchicalConsistencyLoss(nn.Module):
    """Twin-head BCE + parent-consistency penalties.

    Parameters
    ----------
    tactic_parent_matrix : [num_techniques, num_tactics] float (1 = parent)
    base_parent_matrix   : [num_techniques, num_techniques] float (1 = base of a sub-technique)
    """

    def __init__(self, tactic_parent_matrix: torch.Tensor, base_parent_matrix: torch.Tensor,
                 lambda_tactic: float = config.LAMBDA_TACTIC_CONSISTENCY,
                 lambda_subtech: float = config.LAMBDA_SUBTECH_CONSISTENCY,
                 pos_weight_tactic: Optional[torch.Tensor] = None,
                 pos_weight_technique: Optional[torch.Tensor] = None):
        super().__init__()
        # Registered as buffers so they move with .to(device) and serialise.
        self.register_buffer("M_tac", tactic_parent_matrix.float())      # [T, A]
        self.register_buffer("M_base", base_parent_matrix.float())       # [T, T]
        self.lambda_tactic = lambda_tactic
        self.lambda_subtech = lambda_subtech

        self.bce_tactic = nn.BCEWithLogitsLoss(pos_weight=pos_weight_tactic)
        self.bce_technique = nn.BCEWithLogitsLoss(pos_weight=pos_weight_technique)

        # Which techniques actually have a parent (for masking the penalty mean).
        self.register_buffer("has_tactic_parent", (self.M_tac.sum(dim=1) > 0).float())  # [T]
        self.register_buffer("has_base_parent", (self.M_base.sum(dim=1) > 0).float())   # [T]

    @staticmethod
    def _parent_prob(child_prob_source: torch.Tensor, parent_prob: torch.Tensor,
                     parent_matrix: torch.Tensor) -> torch.Tensor:
        """For each child, the max probability among its parents.

        child_prob_source is unused for the gather; we compute, per child c,
        max_p( parent_prob[:, p] ) over parents p where matrix[c, p] == 1.
        Returns [B, num_children].
        """
        # parent_prob: [B, P] ; parent_matrix: [C, P]
        # broadcast -> [B, C, P]; zero-out non-parents, then max over P.
        masked = parent_prob.unsqueeze(1) * parent_matrix.unsqueeze(0)  # [B, C, P]
        return masked.max(dim=2).values  # [B, C]

    def forward(self, tactic_logits: torch.Tensor, technique_logits: torch.Tensor,
                tactic_targets: torch.Tensor, technique_targets: torch.Tensor
                ) -> Tuple[torch.Tensor, Dict[str, float]]:
        bce_a = self.bce_tactic(tactic_logits, tactic_targets)
        bce_b = self.bce_technique(technique_logits, technique_targets)

        p_tac = torch.sigmoid(tactic_logits)        # [B, A]
        p_tech = torch.sigmoid(technique_logits)    # [B, T]

        # (1) Technique -> Tactic: penalise prob mass above the parent tactic.
        parent_tac_prob = self._parent_prob(p_tech, p_tac, self.M_tac)        # [B, T]
        viol_tac = F.relu(p_tech - parent_tac_prob) * self.has_tactic_parent.unsqueeze(0)
        denom_tac = self.has_tactic_parent.sum().clamp(min=1.0)
        loss_tac = viol_tac.sum(dim=1).mean() / denom_tac

        # (2) Sub-technique -> base Technique.
        parent_base_prob = self._parent_prob(p_tech, p_tech, self.M_base)     # [B, T]
        viol_base = F.relu(p_tech - parent_base_prob) * self.has_base_parent.unsqueeze(0)
        denom_base = self.has_base_parent.sum().clamp(min=1.0)
        loss_base = viol_base.sum(dim=1).mean() / denom_base

        total = bce_a + bce_b + self.lambda_tactic * loss_tac + self.lambda_subtech * loss_base
        components = {
            "loss": float(total.detach().cpu()),
            "bce_tactic": float(bce_a.detach().cpu()),
            "bce_technique": float(bce_b.detach().cpu()),
            "consistency_tactic": float(loss_tac.detach().cpu()),
            "consistency_subtech": float(loss_base.detach().cpu()),
        }
        return total, components
