"""
threat_pipeline.logic_engine  —  LAYER 3: Constraint & Logic Engine
===================================================================
A deterministic gatekeeper. It takes the Layer 1 extraction (relations +
context) and the Layer 2 vector candidates, then applies strict cybersecurity
rules to *eliminate*, *penalise*, or *boost* each candidate. The output is a
final, adjusted-confidence mapping — no probabilities are invented, every change
is traceable to a named rule.

This is where naive keyword/embedding matches get corrected. The vector DB might
say "this looks 0.7 like Non-Application Layer Protocol", but if the traffic is
on port 443/HTTPS that's logically impossible — the engine vetoes it.

Adding a rule = add one method and register it in ``self.rules``. Each rule
returns zero or more ``Adjustment`` objects.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, List

from . import config
from .schema import Extraction, LogContext, MappedTechnique, RetrievedTechnique

log = logging.getLogger("threat_pipeline.logic_engine")


# Technique IDs the rules reason about explicitly.
T_NON_APP_LAYER = "T1095"        # Non-Application Layer Protocol
T_APP_LAYER = "T1071"            # Application Layer Protocol
T_ENCRYPTED_CHANNEL = "T1573"    # Encrypted Channel
T_EXPLOIT_REMOTE = "T1210"       # Exploitation of Remote Services
T_VALID_ACCOUNTS = "T1078"       # Valid Accounts
T_REMOTE_SERVICES = "T1021"      # Remote Services (incl. RDP/SSH/SMB sub-techniques)
T_EXFIL_ALT_PROTO = "T1048"      # Exfiltration Over Alternative Protocol

# Protocols that ride on top of the application layer.
APP_LAYER_PROTOCOLS = {
    "http", "https", "dns", "smtp", "ldap", "ldaps", "imap", "imaps", "pop3",
    "pop3s", "ftp", "ssh", "rdp", "smb", "kerberos", "winrm", "telnet", "snmp",
    "mysql", "mssql", "tls", "ssl",
}
NON_APP_LAYER_PROTOCOLS = {"icmp", "gre", "raw", "arp"}

# Boost/penalty factors (multiplicative on the similarity-derived base score).
BOOST = 1.30
STRONG_BOOST = 1.55
PENALTY = 0.55
ELIMINATE = 0.0


@dataclass
class Adjustment:
    factor: float       # multiplier; 0.0 == hard eliminate
    reason: str
    eliminate: bool = False


# A rule maps (candidate, context, extraction) -> list of adjustments.
Rule = Callable[[RetrievedTechnique, LogContext, Extraction], List[Adjustment]]


class ConstraintEngine:
    """Deterministic gatekeeper over Layer 2 candidates."""

    def __init__(self) -> None:
        self.rules: List[Rule] = [
            self._rule_protocol_layer,
            self._rule_remote_access_dependency,
            self._rule_platform,
            self._rule_evidence_reinforcement,
        ]

    # -- public API ---------------------------------------------------------
    def evaluate(
        self,
        candidates: List[RetrievedTechnique],
        extraction: Extraction,
    ) -> List[MappedTechnique]:
        ctx = extraction.context
        mapped: List[MappedTechnique] = []

        for cand in candidates:
            base = float(cand.similarity)
            score = base
            eliminated = False
            reasons: List[str] = []

            for rule in self.rules:
                for adj in rule(cand, ctx, extraction):
                    reasons.append(adj.reason)
                    if adj.eliminate or adj.factor == ELIMINATE:
                        eliminated = True
                        score = 0.0
                    else:
                        score *= adj.factor

            score = max(0.0, min(1.0, score))

            if eliminated:
                status = "eliminated"
            elif score >= config.ACCEPT_THRESHOLD:
                status = "accepted"
            else:
                status = "suppressed"

            mapped.append(
                MappedTechnique(
                    id=cand.id,
                    name=cand.name,
                    tactic=cand.tactic,
                    base_confidence=round(base, 3),
                    adjusted_confidence=round(score, 3),
                    status=status,
                    reasons=reasons or ["No constraints triggered; similarity baseline retained."],
                    evidence=self._evidence_for(cand, extraction),
                )
            )

        # Highest-confidence accepted techniques first.
        mapped.sort(
            key=lambda m: (m.status == "accepted", m.adjusted_confidence), reverse=True
        )
        return mapped

    # -- rules --------------------------------------------------------------
    def _rule_protocol_layer(self, cand, ctx, extraction) -> List[Adjustment]:
        """Port/protocol logic.

        If application-layer traffic is observed (e.g. port 443 / HTTPS), then
        'Non-Application Layer Protocol' is logically impossible -> eliminate.
        Conversely, application-/encrypted-layer techniques get reinforced.
        """
        adjustments: List[Adjustment] = []
        app_layer = set(ctx.protocols) & APP_LAYER_PROTOCOLS
        non_app_layer = set(ctx.protocols) & NON_APP_LAYER_PROTOCOLS

        base_id = cand.id.split(".")[0]

        if base_id == T_NON_APP_LAYER and app_layer and not non_app_layer:
            proto = sorted(app_layer)[0]
            adjustments.append(
                Adjustment(
                    ELIMINATE,
                    f"Eliminated '{cand.name}': traffic uses application-layer "
                    f"protocol ({proto.upper()}{' / port 443' if 443 in ctx.ports else ''}), "
                    f"contradicting a non-application-layer protocol.",
                    eliminate=True,
                )
            )
        elif base_id in (T_APP_LAYER, T_EXFIL_ALT_PROTO) and app_layer:
            proto = sorted(app_layer)[0]
            adjustments.append(
                Adjustment(BOOST, f"Reinforced by observed {proto.upper()} application-layer traffic.")
            )
        elif base_id == T_ENCRYPTED_CHANNEL and ({"https", "tls", "ssl"} & app_layer):
            adjustments.append(
                Adjustment(BOOST, "Reinforced by TLS/HTTPS encryption indicators.")
            )
        elif base_id == T_NON_APP_LAYER and non_app_layer:
            proto = sorted(non_app_layer)[0]
            adjustments.append(
                Adjustment(BOOST, f"Reinforced by non-application-layer protocol ({proto.upper()}).")
            )
        return adjustments

    def _rule_remote_access_dependency(self, cand, ctx, extraction) -> List[Adjustment]:
        """Authorized-access dependency logic.

        Native remote services (RDP/SSH/WinRM) or valid credentials mean the
        adversary *logged in*, they did not *exploit*. So suppress
        'Exploitation of Remote Services' and reinforce 'Valid Accounts' /
        'Remote Services'.
        """
        adjustments: List[Adjustment] = []
        base_id = cand.id.split(".")[0]
        authorized = ctx.uses_valid_credentials or ctx.uses_native_remote_service

        if base_id == T_EXPLOIT_REMOTE and authorized:
            why = "valid credentials" if ctx.uses_valid_credentials else "a native remote service (e.g. RDP/SSH)"
            adjustments.append(
                Adjustment(
                    ELIMINATE,
                    f"Eliminated '{cand.name}': access was via {why}, indicating "
                    f"authorized remote login rather than exploitation.",
                    eliminate=True,
                )
            )
        if base_id == T_VALID_ACCOUNTS and ctx.uses_valid_credentials:
            adjustments.append(
                Adjustment(STRONG_BOOST, "Reinforced by explicit valid/compromised credential usage.")
            )
        if base_id == T_REMOTE_SERVICES and ctx.uses_native_remote_service:
            adjustments.append(
                Adjustment(BOOST, "Reinforced by native remote-service session in the log.")
            )
        return adjustments

    def _rule_platform(self, cand, ctx, extraction) -> List[Adjustment]:
        """OS consistency.

        If the log is clearly Linux/macOS, drop techniques that only apply to
        Windows (and vice-versa). Techniques with no platform metadata, or that
        list the detected OS, are left untouched.
        """
        if ctx.platform == "unknown" or not cand.platforms:
            return []
        tech_platforms = {p.strip().lower() for p in cand.platforms}
        # Normalise: many techniques list e.g. "Windows", "Linux", "macOS".
        if ctx.platform not in tech_platforms:
            return [
                Adjustment(
                    ELIMINATE,
                    f"Eliminated '{cand.name}': applies to {sorted(tech_platforms)} but "
                    f"telemetry is {ctx.platform}.",
                    eliminate=True,
                )
            ]
        return []

    def _rule_evidence_reinforcement(self, cand, ctx, extraction) -> List[Adjustment]:
        """Lexical corroboration.

        If a named tool/target from Layer 1 appears verbatim in the candidate's
        description, the match is more than embedding coincidence -> small boost.
        """
        haystack = (cand.name + " " + cand.description).lower()
        tokens: List[str] = []
        for rel in extraction.relations:
            for val in (rel.tool, rel.target):
                if val and len(val) >= 4 and val.lower() in haystack:
                    tokens.append(val)
        if tokens:
            uniq = sorted(set(tokens))
            return [Adjustment(BOOST, f"Lexically corroborated by: {', '.join(uniq)}.")]
        return []

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _evidence_for(cand: RetrievedTechnique, extraction: Extraction) -> List[str]:
        ev: List[str] = []
        if cand.source_query:
            ev.append(cand.source_query)
        haystack = (cand.name + " " + cand.description).lower()
        for rel in extraction.relations:
            for val in (rel.tool, rel.target):
                if val and len(val) >= 4 and val.lower() in haystack and val not in ev:
                    ev.append(val)
        return ev[:5]


# App-wide singleton.
constraint_engine = ConstraintEngine()
