"""
threat_pipeline.command_intent  —  LOLBin / CLI intent enrichment
=================================================================
Terse command-line IOCs ("vssadmin Delete Shadows") embed poorly against MITRE
ATT&CK's natural-language technique descriptions, so the bi-encoder retriever
mis-ranks them (e.g. it scored "Winlogon Helper DLL" above "Inhibit System
Recovery" for a shadow-copy deletion command). This module deterministically
appends *intent vocabulary* — phrased in MITRE's own description words — to a
retrieval query whenever it recognises a known living-off-the-land binary
(LOLBin) or command signature, bridging the command->prose semantic gap *before*
the query reaches the embedding model.

Design contract:
  * **Additive only.** The original query tokens are always kept; enrichment is
    appended, never substituted. Retrieval recall can only improve.
  * **Grounded.** A signature fires only when *all* of its trigger tokens appear
    verbatim in the query, so it cannot invent intent for a command that is not
    present. Matching is token-set containment (order-independent) because the
    extractor reorders fields into "action tool target modifier".
  * **Evidence-safe.** Enrichment is used purely for embedding; the retriever
    keeps the un-enriched query as ``source_query`` so user-facing evidence stays
    faithful to the log.
"""
from __future__ import annotations

import re
from typing import List, Set, Tuple

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Each entry: (required trigger tokens — ALL must be present, intent phrase).
# Triggers are matched against the lower-cased token set of the query, so
# "vssadmin.exe" -> {"vssadmin", "exe"} and field order does not matter. Intent
# phrases deliberately use MITRE technique-description vocabulary so they align
# with the indexed corpus text.
_SIGNATURES: List[Tuple[Set[str], str]] = [
    # --- Impact: Inhibit System Recovery (T1490) -------------------------------
    ({"vssadmin", "shadow"}, "inhibit system recovery delete volume shadow copies backups"),
    ({"vssadmin", "shadows"}, "inhibit system recovery delete volume shadow copies backups"),
    ({"shadowcopy", "delete"}, "inhibit system recovery delete volume shadow copies"),
    ({"delete", "shadows"}, "inhibit system recovery delete volume shadow copies"),
    ({"wbadmin", "delete"}, "inhibit system recovery delete backup catalog"),
    ({"bcdedit", "recoveryenabled"}, "inhibit system recovery disable boot recovery"),
    ({"bcdedit", "bootstatuspolicy"}, "inhibit system recovery ignore boot failures"),
    ({"wmic", "shadowcopy"}, "inhibit system recovery delete volume shadow copies"),

    # --- Impact: Data Destruction / Defacement --------------------------------
    ({"cipher", "/w"}, "data destruction overwrite deleted data wipe disk"),
    ({"format", "/y"}, "disk wipe data destruction"),

    # --- Defense Evasion: Indicator Removal (T1070) ---------------------------
    ({"wevtutil", "cl"}, "indicator removal clear windows event logs"),
    ({"clear", "eventlog"}, "indicator removal clear windows event logs"),
    ({"fsutil", "usn"}, "indicator removal delete usn change journal"),
    ({"fsutil", "deletejournal"}, "indicator removal delete usn change journal"),

    # --- Defense Evasion: Impair Defenses (T1562) -----------------------------
    ({"netsh", "advfirewall"}, "impair defenses disable or modify system firewall"),
    ({"netsh", "firewall"}, "impair defenses disable or modify system firewall"),
    ({"set-mppreference", "disablerealtimemonitoring"}, "impair defenses disable antivirus tools"),
    ({"sc", "stop"}, "impair defenses disable or modify services tools"),

    # --- Defense Evasion: Signed Binary Proxy Execution (T1218) ----------------
    ({"rundll32"}, "signed binary proxy execution rundll32"),
    ({"regsvr32"}, "signed binary proxy execution regsvr32 squiblydoo"),
    ({"mshta"}, "signed binary proxy execution mshta html application"),
    ({"installutil"}, "signed binary proxy execution installutil"),

    # --- Command and Control / Ingress Tool Transfer (T1105) -------------------
    ({"certutil", "urlcache"}, "ingress tool transfer download remote file"),
    ({"certutil", "decode"}, "deobfuscate decode files certutil"),
    ({"bitsadmin", "transfer"}, "ingress tool transfer background intelligent transfer service"),

    # --- Execution: Scheduled Task / Service (T1053 / T1543) -------------------
    ({"schtasks", "create"}, "scheduled task job persistence"),
    ({"sc", "create"}, "create or modify system service persistence"),

    # --- Credential Access: OS Credential Dumping (T1003) ---------------------
    ({"reg", "sam"}, "os credential dumping security account manager registry hive"),
    ({"reg", "save"}, "os credential dumping registry hive dump"),
    ({"ntdsutil", "ifm"}, "os credential dumping ntds active directory database"),
    ({"procdump", "lsass"}, "os credential dumping lsass process memory"),
    # Mimikatz family (T1003.001 — LSASS Memory).
    ({"mimikatz"}, "os credential dumping lsass memory credential theft"),
    ({"mimi"}, "os credential dumping lsass memory credential theft"),
    ({"sekurlsa"}, "os credential dumping lsass memory credential theft logonpasswords"),

    # --- Lateral Movement: Remote Services / Admin Shares (T1021.002 / T1570) --
    ({"psexec"}, "remote services smb windows admin shares lateral tool transfer lateral movement"),
    ({"paexec"}, "remote services smb windows admin shares lateral tool transfer lateral movement"),

    # --- Discovery (T1033 / T1087 / T1482) ------------------------------------
    ({"whoami"}, "system owner user discovery"),
    ({"nltest", "domain_trusts"}, "domain trust discovery"),
    ({"net", "group"}, "permission groups domain account discovery"),
]


# Literal substring triggers — for signatures that contain characters the word
# tokenizer drops (e.g. the "$" in Windows admin shares like ADMIN$ / C$ / IPC$).
_SUBSTRING_SIGNATURES: List[Tuple[str, str]] = [
    ("admin$", "smb windows admin shares lateral movement remote services"),
    ("ipc$", "smb windows admin shares remote services"),
    ("c$", "smb windows admin shares lateral movement"),
]


def enrich(query: str) -> str:
    """Append intent vocabulary for any recognised command signature.

    Returns the original query unchanged when nothing matches. Multiple matching
    signatures each contribute their phrase once (de-duplicated, original order).
    """
    if not query:
        return query
    low = query.lower()
    tokens = set(_TOKEN_RE.findall(low))
    if not tokens:
        return query

    seen: Set[str] = set()
    extra: List[str] = []
    for required, intent in _SIGNATURES:
        if required <= tokens and intent not in seen:
            seen.add(intent)
            extra.append(intent)
    for trigger, intent in _SUBSTRING_SIGNATURES:
        if trigger in low and intent not in seen:
            seen.add(intent)
            extra.append(intent)
    if not extra:
        return query
    return query + " " + " ".join(extra)
