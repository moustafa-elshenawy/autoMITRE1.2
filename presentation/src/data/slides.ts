export type SlideWidget =
  | 'latency'
  | 'accuracy'
  | 'architecture'
  | 'simulator'
  | 'guardrail'
  | 'hardware'
  | 'dbscan'
  | 'intake'
  | 'siem_funnel'
  | 'stix_tree'
  | 'lit_review_layer'
  // New widgets
  | 'threat_surge'
  | 'fragmentation_map'
  | 'alert_fatigue_meter'
  | 'manual_mapping_hell'
  | 'gap_venn'
  | 'comparison_radar'
  | 'comparison_table'
  | 'contribution_bridge'
  | 'objectives_grid'
  | 'stakeholder_orbit'
  | 'fr_pipeline'
  | 'nfr_radar'
  | 'design_decision_tree'
  | 'arch_overview'
  | 'nlp_pipeline'
  | 'pcap_flow'
  | 'securebert_brain'
  | 'rag_mechanism'
  | 'llm_failover'
  | 'framework_mapper'
  | 'mitigation_flow'
  | 'api_routes'
  | 'tech_stack_wheel'
  | 'test_matrix'
  | 'mapping_accuracy'
  | 'case_study_walkthrough'
  | 'accuracy_context'
  | 'failover_test'
  | 'load_test'
  | 'fr_validation'
  | 'limitations_gauge'
  | 'future_roadmap'
  | 'conclusion_shield'
  | 'none';

export type SlideData = {
  id: number;
  section: string;
  title: string;
  content: string[];
  widget?: SlideWidget;
  layout?: 'title' | 'content' | 'split';
};

export const slides: SlideData[] = [

  // ────────────────────────────────────────────────────────────
  // SECTION 1 — OPENING (Slides 1–4)
  // ────────────────────────────────────────────────────────────
  {
    id: 1,
    section: 'Opening',
    title: 'autoMITRE: AI-Powered Threat Intelligence & Mitigation System',
    content: [
      'A Unified Platform for Automated Threat Analysis and SOC Orchestration',
      'Bridging Static Risk Design with Active, Framework-Aligned Cyber Defense',
      'B.Sc. Graduation Project — Arab Academy for Science, Technology & Maritime Transport',
    ],
    layout: 'title',
  },
  {
    id: 2,
    section: 'Opening',
    title: 'Team & Supervision',
    content: [
      'Moustafa Ahmed Elsayed Elshenawy',
      'Abd El-Rahman Mohammed Abd-Eltawab',
      'Hashem Abdo Hashem',
      'Mira Amin',
      'Jana Wael',
      'Jomana Mohsen',
      'Supervisor: Dr. Ahmed Maher Moustafa | AASTMT Smart Village | 2025–2026',
    ],
    layout: 'split',
    widget: 'stakeholder_orbit',
  },
  {
    id: 3,
    section: 'Opening',
    title: 'Agenda — What We Will Cover Today',
    content: [
      '① The Problem — Why existing SOC workflows are broken',
      '② The Gap — Where current tools fall short',
      '③ Requirements & Design — How we engineered the solution',
      '④ The AI Engine — SecureBERT, RAG, LLM, and the full stack',
      '⑤ Results & Testing — 96.81% accuracy, 37 test cases, IEEE 829',
      '⑥ Conclusion & Future Work — What comes next',
    ],
    layout: 'split',
    widget: 'objectives_grid',
  },
  {
    id: 4,
    section: 'Opening',
    title: 'The Threat Landscape is Evolving Faster Than Defenses',
    content: [
      '562% surge in global cyber incidents since 2019 — attacks outpace defenses.',
      'APTs, ransomware, and insider threats demand multi-layered, continuous analysis.',
      'Manual analysis cannot scale to the volume and velocity of modern threats.',
    ],
    layout: 'split',
    widget: 'threat_surge',
  },

  // ────────────────────────────────────────────────────────────
  // SECTION 2 — THE PROBLEM & GAP (Slides 5–10)
  // ────────────────────────────────────────────────────────────
  {
    id: 5,
    section: 'The Problem & Gap',
    title: 'Fragmented SOC Tooling — The Root Cause',
    content: [
      'Microsoft TMT, OWASP Dragon, Network Logs, VirusTotal, and Splunk all operate in isolation.',
      'No tool bridges design-time threat models with runtime log analysis.',
      'Analysts manually correlate findings across 5+ disconnected platforms every incident.',
    ],
    layout: 'split',
    widget: 'fragmentation_map',
  },
  {
    id: 6,
    section: 'The Problem & Gap',
    title: 'Alert Fatigue — The SOC Analyst Bottleneck',
    content: [
      '10,000+ daily alerts per analyst — the human filtering ceiling has been exceeded.',
      'High false-positive rates cause genuine threats to be buried in noise.',
      'MTTD (Mean Time to Detect) averages 207 days in the industry — far too slow.',
    ],
    layout: 'split',
    widget: 'alert_fatigue_meter',
  },
  {
    id: 7,
    section: 'The Problem & Gap',
    title: 'Manual MITRE Mapping — A Bottleneck in Every Incident',
    content: [
      'Analysts spend 15–40 minutes per incident manually mapping to ATT&CK techniques.',
      'MITRE ATT&CK contains 499+ unique techniques requiring domain expertise to navigate.',
      'During active incidents, this delay directly increases Mean Time to Respond (MTTR).',
    ],
    layout: 'split',
    widget: 'manual_mapping_hell',
  },
  {
    id: 8,
    section: 'The Problem & Gap',
    title: 'Problem Statement — The Exact Research Gap',
    content: [
      'No unified platform exists that combines AI, multi-format ingestion, and multi-framework mapping.',
      'Current tools are reactive: they report past events but cannot predict future attack paths.',
      'Intelligence outputs are not SIEM-compatible — requiring additional manual reformatting.',
    ],
    layout: 'split',
    widget: 'gap_venn',
  },
  {
    id: 9,
    section: 'Literature Review',
    title: 'Reviewing the State of the Art',
    content: [
      'Microsoft Threat Modeling Tool: Excellent for STRIDE, but purely static and lacks runtime log analysis.',
      'OWASP Threat Dragon: Open-source, diagram-first, but relies heavily on manual human input.',
      'VirusTotal / OSINT Platforms: Strong signature detection but zero contextual mapping to MITRE T-Codes.',
      'Core Philosophy: autoMITRE acts as an enhancement layer to integrate with these existing tools, not a replacement for them.',
    ],
    layout: 'split',
    widget: 'lit_review_layer',
  },

  // ────────────────────────────────────────────────────────────
  // SECTION 3 — REQUIREMENTS & DESIGN (Slides 10–15)
  // ────────────────────────────────────────────────────────────
  {
    id: 10,
    section: 'Requirements & Design',
    title: 'autoMITRE Contribution — Filling the Gap',
    content: [
      'Unified Intelligence: One platform ingests 7 input formats and maps to 4 frameworks.',
      'AI + Grounded RAG: SecureBERT embeddings anchored to verified framework definitions.',
      'Privacy-First: Full offline operation — no sensitive data ever sent to public clouds.',
    ],
    layout: 'split',
    widget: 'contribution_bridge',
  },
  {
    id: 11,
    section: 'Requirements & Design',
    title: 'System Stakeholders — Who Benefits',
    content: [
      'Primary: SOC Analysts and System Administrators benefit from automated threat correlation.',
      'Secondary: IR Teams, Security Engineers, and Compliance Officers gain explainable outputs.',
      'Technical: Developers and AI Engineers can extend the modular pipeline architecture.',
    ],
    layout: 'split',
    widget: 'stakeholder_orbit',
  },
  {
    id: 12,
    section: 'Requirements & Design',
    title: 'Functional Requirements (IEEE 830) — The 9 Core Capabilities',
    content: [
      'FR1: Secure authentication & RBAC (Analyst / Administrator roles).',
      'FR2–FR9: Multi-format upload → AI analysis → Framework mapping → Mitigation gen → SIEM export.',
      'All 9 FRs were formally validated with 37 test cases — 100% PASS rate.',
    ],
    layout: 'split',
    widget: 'fr_pipeline',
  },
  {
    id: 13,
    section: 'Requirements & Design',
    title: 'Non-Functional Requirements (IEEE 830) — Quality Attributes',
    content: [
      'NFR1 Performance: Cloud inference < 1.2s; local inference 4–6.5s (within hardware limits).',
      'NFR5 Security: Input sanitization (95% coverage), RBAC enforcement, no data leakage.',
      'NFR8 Interoperability: Outputs validated for Splunk, QRadar, Wazuh, and Elastic Security.',
    ],
    layout: 'split',
    widget: 'nfr_radar',
  },
  {
    id: 14,
    section: 'Requirements & Design',
    title: 'Design Alternatives Evaluated',
    content: [
      'Alt 1 — Rule-Based Only: Rejected. High explainability but poor unknown-threat coverage.',
      'Alt 2 — ML Only: Rejected. Requires large labeled datasets and poor interpretability.',
      'Selected — Hybrid Rule + ML + NLP: Best accuracy, explainability, and academic feasibility.',
    ],
    layout: 'split',
    widget: 'design_decision_tree',
  },
  {
    id: 15,
    section: 'Requirements & Design',
    title: 'High-Level System Architecture — 4 Layers',
    content: [
      'Input Layer: 7 heterogeneous formats normalized into a unified JSON threat schema.',
      'AI Engine: SecureBERT classifier + ChromaDB RAG + Groq LLM + local Phi-3.5 fallback.',
      'Mapping Layer: Cosine similarity engine correlating threats to 4 frameworks simultaneously.',
      'Output Layer: React dashboard, STIX 2.1, JSON, and PDF exports.',
    ],
    layout: 'split',
    widget: 'arch_overview',
  },

  // ────────────────────────────────────────────────────────────
  // SECTION 4 — THE AI ENGINE (Slides 16–25)
  // ────────────────────────────────────────────────────────────
  {
    id: 16,
    section: 'The AI Engine',
    title: 'Multi-Format Data Ingestion Layer',
    content: [
      'Text Descriptions: Raw CTI reports, analyst notes, and threat narratives.',
      'Structured Inputs: IriusRisk HTML (dual-schema), JSON threat models, CSV/Excel tabular data.',
      'Binary Inputs: PCAP network captures (Scapy), MD5/SHA256 malware hashes (VirusTotal API).',
    ],
    layout: 'split',
    widget: 'intake',
  },
  {
    id: 17,
    section: 'The AI Engine',
    title: 'Text & Threat Description Pipeline — NLP Processing',
    content: [
      'Tokenization: spaCy and NLTK preprocess unstructured text into semantic tokens.',
      'Named Entity Recognition: Extracts attack actors, tools, targets, and actions from prose.',
      'Embedding: all-mpnet-base-v2 generates 768-dimensional semantic threat vectors.',
    ],
    layout: 'split',
    widget: 'nlp_pipeline',
  },
  {
    id: 18,
    section: 'The AI Engine',
    title: 'Isolated Pipeline — PCAP Network Analysis',
    content: [
      'Packet Parsing: Scapy performs header inspection and reconstructs TCP/UDP flow sessions.',
      'Feature Extraction: src/dst IPs, ports, protocols, flags, payload size, inter-packet timing.',
      'Behavioral Classification: Detects beaconing, port scanning, and C2 patterns.',
    ],
    layout: 'split',
    widget: 'pcap_flow',
  },
  {
    id: 19,
    section: 'The AI Engine',
    title: 'SecureBERT — The Domain-Specific AI Classifier',
    content: [
      'Cybersecurity-Trained: Pre-trained on 20,736 threat narratives across all 499 ATT&CK techniques.',
      'Superior Performance: 96.81% accuracy, 96.65% F1-Score — outperforms generic BERT models.',
      'Severity Scoring: Classifies threats into CVSS-aligned severity levels at 95.22% F1-Score.',
    ],
    layout: 'split',
    widget: 'securebert_brain',
  },
  {
    id: 20,
    section: 'The AI Engine',
    title: 'RAG — Retrieval-Augmented Generation for Grounded Outputs',
    content: [
      'Vector Database: ChromaDB stores verified ATT&CK, D3FEND, NIST, and OWASP definitions.',
      'Semantic Retrieval: Cosine similarity finds top-k most relevant framework entries per threat.',
      'Hallucination Prevention: LLM outputs are anchored to retrieved framework context — no fabricated IDs.',
    ],
    layout: 'split',
    widget: 'rag_mechanism',
  },
  {
    id: 21,
    section: 'The AI Engine',
    title: 'LLM Reasoning — Cloud Engine + Local Failover',
    content: [
      'Primary: Groq Cloud API (LPU-powered) delivers reasoning at ~0.8s average latency.',
      'Fallback: Phi-3.5-mini-instruct quantized to Q4_K_M, running via llama_cpp + Apple Metal MPS.',
      'Zero Downtime: Automatic exception-based routing — no analyst intervention required during failover.',
    ],
    layout: 'split',
    widget: 'llm_failover',
  },
  {
    id: 22,
    section: 'The AI Engine',
    title: 'Multi-Framework Mapping Engine',
    content: [
      'Single-Pass Correlation: One threat maps to ATT&CK, D3FEND, NIST 800-53, and OWASP ASVS.',
      'Semantic Similarity: Cosine distance between threat vectors and framework embeddings.',
      'Accuracy: 84.06% for ATT&CK (semantic) and 98.41% for D3FEND/NIST (deterministic).',
    ],
    layout: 'split',
    widget: 'framework_mapper',
  },
  {
    id: 23,
    section: 'The AI Engine',
    title: 'Mitigation Generation Pipeline',
    content: [
      'Step 1 Detect: AI identifies threat intent, target, and attack technique from input.',
      'Step 2 Map: Correlate to ATT&CK, D3FEND, and NIST — produce defensive control IDs.',
      'Steps 3–4 Reason & Recommend: LLM generates explainable step-by-step mitigation actions.',
    ],
    layout: 'split',
    widget: 'mitigation_flow',
  },
  {
    id: 24,
    section: 'The AI Engine',
    title: 'FastAPI Async REST Architecture',
    content: [
      'Asynchronous Endpoints: All routes use async/await — no blocking I/O during file analysis.',
      'Modular Routers: Isolated pipelines for text, PCAP, file hash, threat DB, and SIEM export.',
      'Performance Target: Met NFR1 — API responses at sub-second for most endpoints.',
    ],
    layout: 'split',
    widget: 'api_routes',
  },
  {
    id: 25,
    section: 'The AI Engine',
    title: 'Technology Stack — Tools & Libraries',
    content: [
      'Backend: Python 3.13, FastAPI, Uvicorn, SQLAlchemy ORM, aiosqlite, SQLite.',
      'AI/ML: SecureBERT, all-mpnet-base-v2, ChromaDB, llama_cpp, Groq API, MLX/Metal.',
      'Frontend: React.js 18, Vite, TypeScript, Recharts, Framer Motion, Lucide Icons.',
    ],
    layout: 'split',
    widget: 'tech_stack_wheel',
  },

  // ────────────────────────────────────────────────────────────
  // SECTION 5 — RESULTS & TESTING (Slides 26–35)
  // ────────────────────────────────────────────────────────────
  {
    id: 26,
    section: 'Results & Testing',
    title: 'Testing Framework — IEEE 829 Standard',
    content: [
      'Test Plan Structure: Three domains — Unit/Integration, AI Quantitative, and E2E System testing.',
      'Test Coverage: 37 formal test cases (TC-01 to TC-37) spanning all 9 Functional Requirements.',
      'Outcome: 37 / 37 PASS (100%) — 0 Failures, 0 Blocked, 0 Deferred.',
    ],
    layout: 'split',
    widget: 'test_matrix',
  },
  {
    id: 27,
    section: 'Results & Testing',
    title: 'AI Model Accuracy — SecureBERT Evaluation',
    content: [
      'Dataset: 20,736 cyber threat narratives across all 499 MITRE ATT&CK techniques.',
      'Core Classification: 96.81% Accuracy and 96.65% F1-Score.',
      'Severity Scoring: 95.22% F1-Score for CVSS-aligned threat severity classification.',
    ],
    layout: 'split',
    widget: 'accuracy',
  },
  {
    id: 28,
    section: 'Results & Testing',
    title: 'Inference Latency Benchmarks',
    content: [
      'Groq Cloud (Primary): ~0.8–1.2 seconds average per request using LPU-powered inference.',
      'Local Phi-3.5 (Fallback): 4.0–6.5 seconds depending on prompt length via Apple Metal MPS.',
      'Both modes meet NFR1 performance targets — fully operational within hardware constraints.',
    ],
    layout: 'split',
    widget: 'latency',
  },
  {
    id: 29,
    section: 'Results & Testing',
    title: 'Framework Mapping Accuracy',
    content: [
      'ATT&CK Semantic Mapping: 84.06% accuracy — semantic cosine similarity across 499 techniques.',
      'D3FEND + NIST 800-53: 98.41% accuracy — deterministic rule-based framework correlation.',
      'A single detected threat reliably populates all four frameworks in one automated pass.',
    ],
    layout: 'split',
    widget: 'mapping_accuracy',
  },
  {
    id: 30,
    section: 'Results & Testing',
    title: 'Contextualizing 84% Accuracy',
    content: [
      'Sub-technique Ambiguity: 499 techniques have massive semantic overlap (e.g., T1003.001 vs T1003.004).',
      'Probabilistic Nature: Zero-shot semantic search retrieves based on generic embeddings, lacking domain nuance.',
      'Isolated Context: Logs are analyzed in a vacuum. Analysts use surrounding timeline context to map correctly.',
    ],
    layout: 'split',
    widget: 'accuracy_context',
  },
  {
    id: 31,
    section: 'Results & Testing',
    title: 'Case Study — Mimikatz Credential Dumping',
    content: [
      'Input: "adversary uses Mimikatz to dump credential material from LSASS"',
      'Mapped to: T1003.001 (OS Credential Dumping) | D3FEND: Process Isolation | NIST AC-6',
      'Mitigation: Credential Guard + Mimikatz signature blocking + PAW — generated in 1.2 seconds.',
    ],
    layout: 'split',
    widget: 'case_study_walkthrough',
  },
  {
    id: 32,
    section: 'Results & Testing',
    title: 'SIEM Integration — STIX 2.1 Export Validation',
    content: [
      'STIX 2.1 Objects: Detected threats are structured as Bundle → Indicator → AttackPattern objects.',
      'Compatibility: Validated ingestion into Splunk Enterprise Security and Wazuh dashboards.',
      'Export Formats: STIX 2.1 JSON, plain JSON, and CSV — covering all major SIEM platforms.',
    ],
    layout: 'split',
    widget: 'stix_tree',
  },
  {
    id: 33,
    section: 'Results & Testing',
    title: 'Hallucination Prevention — RAG Validation',
    content: [
      'Problem: Generic LLMs hallucinate non-existent ATT&CK IDs and fabricate defense mappings.',
      'RAG Solution: Every LLM output is anchored to retrieved ChromaDB framework definitions.',
      'Result: Zero hallucinated technique IDs in all 37 test runs — 100% framework-verified outputs.',
    ],
    layout: 'split',
    widget: 'guardrail',
  },
  {
    id: 34,
    section: 'Results & Testing',
    title: 'System Resiliency — Failover Test (TC-33)',
    content: [
      'Test: Groq Cloud API artificially blocked during active threat processing session.',
      'Result: Exception handler automatically redirected to local Phi-3.5-mini within 0.3 seconds.',
      'Zero Downtime: All 12 queued threat analyses completed — no crashes, no data loss.',
    ],
    layout: 'split',
    widget: 'failover_test',
  },
  {
    id: 35,
    section: 'Results & Testing',
    title: 'Load Testing — 20 Concurrent Analysts (Locust)',
    content: [
      'Load Profile: Simulated 1 → 20 concurrent analysts uploading files simultaneously.',
      'Result: Linear latency degradation (0.8s → 5.1s) — no server timeouts or connection drops.',
      'Degradation Pattern: Predictable, manageable scaling within SOC analyst workstation limits.',
    ],
    layout: 'split',
    widget: 'load_test',
  },
  {
    id: 36,
    section: 'Results & Testing',
    title: 'Functional Requirements Validation — Complete Coverage',
    content: [
      '9 Functional Requirements — all formally validated against dedicated test case ranges.',
      'All test cases PASS: Authentication, Upload, AI Analysis, Mapping, Mitigation, SIEM Export.',
      'NFRs met: Performance (< 1.2s), Security (95% sanitization coverage), Interoperability (STIX).',
    ],
    layout: 'split',
    widget: 'fr_validation',
  },

  // ────────────────────────────────────────────────────────────
  // SECTION 6 — CONCLUSION & FUTURE WORK (Slides 36–39)
  // ────────────────────────────────────────────────────────────
  {
    id: 37,
    section: 'Conclusion & Future Work',
    title: 'Honest Limitations',
    content: [
      'PCAP Heuristic Accuracy: 63.2% — behavioral baseline detection only (no deep-learning DPI yet).',
      'Hardware Constraint: 8GB RAM limits local model size and real-time PCAP streaming at scale.',
      'Production Scope: Functional prototype — not yet hardened for enterprise production deployment.',
    ],
    layout: 'split',
    widget: 'limitations_gauge',
  },
  {
    id: 38,
    section: 'Conclusion & Future Work',
    title: 'Future Work — DBSCAN Zero-Day Anomaly Detection',
    content: [
      'DBSCAN Clustering: Density-based unsupervised algorithm groups behavioral anomalies.',
      'Zero-Day Discovery: Clusters logs that match no existing ATT&CK signature — novel threat detection.',
      'Self-Improving: Newly confirmed clusters feed back into the RAG knowledge base automatically.',
    ],
    layout: 'split',
    widget: 'dbscan',
  },
  {
    id: 39,
    section: 'Conclusion & Future Work',
    title: 'Future Enhancement Roadmap',
    content: [
      'Phase 1 (Q3 2026): Fine-tune local models to match cloud accuracy — eliminate offline performance gap.',
      'Phase 2 (Q4 2026): Add Cloud Security Alliance (CSA), ISO 27001, GDPR framework mappings.',
      'Phase 3–4 (2027): Enterprise SecLM/SecPaLM Integration to achieve 95%+ mapping accuracy.',
    ],
    layout: 'split',
    widget: 'future_roadmap',
  },
  {
    id: 40,
    section: 'Conclusion & Future Work',
    title: 'Conclusion & Thank You',
    content: [
      'autoMITRE: A complete AI-powered threat intelligence system — built from the ground up by a team of 6.',
      '96.81% accuracy • 37/37 test cases PASS • 4 frameworks • SIEM-ready — all within 8GB RAM.',
      'The floor is open for Questions & Answers. Thank you for your time and attention.',
    ],
    layout: 'title',
    widget: 'conclusion_shield',
  },
];
