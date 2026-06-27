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
  // SECTION 1: INTRODUCTION & BACKGROUND (Slides 1-8)
  {
    id: 1,
    section: "Introduction & Background",
    title: "autoMITRE: AI-Powered Threat Intelligence and Mitigation System",
    content: [
      "A Unified Platform for Automated Threat Modeling and SOC Orchestration",
      "Bridging the Gap Between Static Risk Design and Active Cyber Defense",
      "Graduation Project Defense — Arab Academy for Science, Technology, and Maritime Transport"
    ],
    layout: "title"
  },
  {
    id: 2,
    section: "Introduction & Background",
    title: "Project Authors & Affiliation",
    content: [
      "Moustafa Ahmed Elsayed Elshenawy (Team Lead & Full-Stack Architect)",
      "Abd El-Rahman Mohammed Abd-Eltawab (Security Analyst & Integrations)",
      "Hashem Abdo Hashem (Backend & Systems Developer)",
      "Mira Amin (AI Engineer & QA Lead)",
      "Jana Wael (Data Engineer)",
      "Jomana Mohsen (Frontend Developer)",
      "College of Computing and Information Technology, AASTMT (Smart Village)"
    ],
    layout: "content"
  },
  {
    id: 3,
    section: "Introduction & Background",
    title: "Academic Supervision",
    content: [
      "Supervisor: Dr. Ahmed Maher Moustafa",
      "Academic Year: 2025-2026",
      "Subject: Graduation Thesis Submitted in Partial Fulfillment of B.Sc. in Cybersecurity"
    ],
    layout: "content"
  },
  {
    id: 4,
    section: "Introduction & Background",
    title: "Core Motivation",
    content: [
      "Evolving Threat Landscape: Rapid increase in sophisticated, multi-stage cyber attacks.",
      "Operational Inefficiencies: Security teams spend hours manually compiling threat models and maps.",
      "Tool Fragmentation: Lack of unified integration between design-time models and real-time logs."
    ],
    layout: "content"
  },
  {
    id: 5,
    section: "Introduction & Background",
    title: "MITRE ATT&CK Framework Primer",
    content: [
      "Standardized Taxonomy: A globally recognized knowledge base of adversary tactics and techniques.",
      "Defensive Utility: Helps SOCs understand attacker behavior, trace threat paths, and verify coverage.",
      "Mapping Challenge: Over 499 unique techniques and sub-techniques require manual, complex correlation."
    ],
    layout: "content"
  },
  {
    id: 6,
    section: "Introduction & Background",
    title: "The Bottleneck of Manual Mapping",
    content: [
      "Unstructured Intelligence: Most CTI data and logs are shared in raw text or disjointed formats.",
      "High Human Overhead: SOC analysts must manually translate threat descriptions to ATT&CK codes.",
      "Delayed Response (MTTR): Manual mapping slows down detection and response workflows during active incidents."
    ],
    layout: "content"
  },
  {
    id: 7,
    section: "Introduction & Background",
    title: "Specific Objectives of autoMITRE",
    content: [
      "Ingest Diverse Inputs: Support PCAP, raw text, XML, JSON, and file hashes automatically.",
      "AI Semantic Parsing: Extract threat behaviors and intent directly from unstructured logs.",
      "Automated Mapping & Mitigations: Link findings to ATT&CK, D3FEND, NIST 800-53, and OWASP ASVS.",
      "SIEM Orchestration: Export standardized STIX 2.1 intelligence to Splunk and QRadar."
    ],
    layout: "content"
  },
  {
    id: 8,
    section: "Introduction & Background",
    title: "Scope and System Boundaries",
    content: [
      "SOC Optimization: Focuses on automating Level 1/Level 2 analyst correlation tasks.",
      "Framework Boundaries: Targets the MITRE ATT&CK Enterprise Matrix and corresponding controls.",
      "Resource Constraint: Designed to operate efficiently on local analyst workstations."
    ],
    layout: "content"
  },

  // SECTION 2: LITERATURE REVIEW & GAP ANALYSIS (Slides 9-12)
  {
    id: 9,
    section: "Literature Review & Gap Analysis",
    title: "Limitations of Current SOC Workflows",
    content: [
      "Alert Fatigue: Analysts are overwhelmed by high volumes of disconnected alerts.",
      "Isolated Data Silos: Threat models sit in static reports while SIEM systems run logs separately.",
      "Reactive Defenses: Systems report previous events but fail to predict next-stage threat actions."
    ],
    layout: "split",
    widget: "siem_funnel"
  },
  {
    id: 10,
    section: "Literature Review & Gap Analysis",
    title: "Existing Automated Solutions & Gaps",
    content: [
      "Microsoft TMT & OWASP Threat Dragon: Generate static STRIDE reports but lack runtime analysis.",
      "IriusRisk: Commercial tool with rule-based templates but lacks adaptive learning or NLP models.",
      "VirusTotal: Detects signatures but does not map behavioral threat paths to security frameworks."
    ],
    layout: "content"
  },
  {
    id: 11,
    section: "Literature Review & Gap Analysis",
    title: "Gaps: Hallucinations and Privacy",
    content: [
      "Cloud LLM Hallucinations: Generic AI models often hallucinate non-existent ATT&CK IDs.",
      "Data Privacy Violations: Uploading internal logs or PCAP files to public APIs exposes sensitive metadata.",
      "autoMITRE Solution: Integrates local vector databases (RAG) and private offline LLM fallbacks."
    ],
    layout: "split",
    widget: "guardrail"
  },
  {
    id: 12,
    section: "Literature Review & Gap Analysis",
    title: "How autoMITRE Addresses the Gaps",
    content: [
      "Unified Pipeline: Bridges static threat modeling with runtime SIEM log analysis.",
      "Grounded Reasoning: Semantic RAG ensures all AI outputs are mapped to verified standards.",
      "Privacy-First Architecture: Supports full offline execution on constrained hardware."
    ],
    layout: "content"
  },

  // SECTION 3: SYSTEM ARCHITECTURE & AI METHODOLOGY (Slides 13-22)
  {
    id: 13,
    section: "System Architecture & AI Methodology",
    title: "High-Level System Architecture",
    content: [
      "Decoupled Architecture: FastAPI backend paired with a responsive React.js frontend.",
      "Modular Pipelines: Dedicated routers isolate data ingestion, AI reasoning, and SIEM exports.",
      "Asynchronous Processing: Ensures high-throughput file analysis without blocking the UI."
    ],
    layout: "split",
    widget: "architecture"
  },
  {
    id: 14,
    section: "System Architecture & AI Methodology",
    title: "Ingestion Layer & Intake Router",
    content: [
      "Multi-Format Ingestion: Accepts raw text, IriusRisk HTML, PCAP files, and MD5/SHA256 hashes.",
      "Validation & Parsing: Normalizes heterogeneous streams into a unified internal JSON threat schema.",
      "Sanitization Layer: Sanitizes inputs to prevent injection attacks (95% coverage)."
    ],
    layout: "split",
    widget: "intake"
  },
  {
    id: 15,
    section: "System Architecture & AI Methodology",
    title: "Threat Preprocessing & Parsing",
    content: [
      "Text Tokenization: Standardizes unstructured text input for model compatibility.",
      "DOM Parsing: Extracts unmitigated threats and system components from IriusRisk HTML files using BeautifulSoup.",
      "Network Flow Construction: Assembles individual packets into distinct communication streams."
    ],
    layout: "content"
  },
  {
    id: 16,
    section: "System Architecture & AI Methodology",
    title: "Isolated Pipeline: Network Logs",
    content: [
      "PCAP Parsing: Leverages Scapy for packet header inspection and flow reconstruction.",
      "Feature Extraction: Extracts source/destination IPs, communication protocols, and packet flags.",
      "Behavioral Normalization: Identifies anomalies like beaconing or scanning for AI classification."
    ],
    layout: "content"
  },
  {
    id: 17,
    section: "System Architecture & AI Methodology",
    title: "Isolated Pipeline: Endpoint & System Logs",
    content: [
      "Log Normalization: Parses structured CSV/JSON log formats from endpoint sources.",
      "Entity Extraction: Identifies system processes, user sessions, file paths, and registry keys.",
      "Correlation Layer: Prepares endpoint metadata for semantic alignment with known attack behaviors."
    ],
    layout: "content"
  },
  {
    id: 18,
    section: "System Architecture & AI Methodology",
    title: "The AI Engine: SecureBERT Integration",
    content: [
      "Domain-Specific Classifier: Deploys Hugging Face SecureBERT pre-trained on cybersecurity corpora.",
      "Semantic Vector Generation: Utilizes `all-mpnet-base-v2` to extract threat semantic contexts.",
      "Superior Performance: Outperforms generic language models in classifying specific security incidents."
    ],
    layout: "content"
  },
  {
    id: 19,
    section: "System Architecture & AI Methodology",
    title: "The AI Engine: RAG Mechanism",
    content: [
      "Local Vector Database: Integrates ChromaDB to store verified cybersecurity framework definitions.",
      "Contextual Grounding: Queries ChromaDB to retrieve verified techniques and mitigation standards.",
      "Hallucination Prevention: Anchors LLM output text directly to retrieved framework standards."
    ],
    layout: "content"
  },
  {
    id: 20,
    section: "System Architecture & AI Methodology",
    title: "The AI Engine: Threat Reasoning",
    content: [
      "Multi-Tiered Inference: Primary reasoning executed via Groq API (`gpt-oss-20b`) for rapid analysis.",
      "Offline Failover: Gracefully redirects to local CPU/GPU engines if network connections are lost.",
      "Local Hardware Accel: Uses Apple Metal (MPS) to execute Phi-3.5-mini locally without memory crashes."
    ],
    layout: "content"
  },
  {
    id: 21,
    section: "System Architecture & AI Methodology",
    title: "Semantic Framework Mapping Logic",
    content: [
      "Cosine Similarity Matching: Computes semantic distance between threat vectors and framework definitions.",
      "Multi-Framework Correlation: Maps single events to ATT&CK, D3FEND, NIST 800-53, and OWASP ASVS.",
      "Dynamic Knowledge Mapping: Resolves complex relationships across multiple defense databases."
    ],
    layout: "split",
    widget: "simulator"
  },
  {
    id: 22,
    section: "System Architecture & AI Methodology",
    title: "Threat Prediction & Forecasting",
    content: [
      "Adaptive Trend Analysis: Mines historical threat records stored in the SQLite database.",
      "Attack Path Forecasting: Predicts next-stage attacker actions based on recognized patterns.",
      "Proactive Defenses: Identifies vulnerable system components before exploitation occurs."
    ],
    layout: "content"
  },

  // SECTION 4: IMPLEMENTATION & ENGINEERING (Slides 23-27)
  {
    id: 23,
    section: "Implementation & Engineering",
    title: "Technology Stack",
    content: [
      "Backend Architecture: Python 3.13, FastAPI, Uvicorn, SQLAlchemy ORM.",
      "AI/ML Components: Hugging Face Transformers, ChromaDB, llama_cpp, MLX.",
      "Frontend Interface: React.js 18, Vite, Tailwind CSS, Lucide Icons, Recharts."
    ],
    layout: "content"
  },
  {
    id: 24,
    section: "Implementation & Engineering",
    title: "Relational Database Schema",
    content: [
      "SQLite Persistence: High performance and low overhead on analyst workstations (`automitre.db`).",
      "Primary Relational Entities: `users`, `threat_records`, `threat_entities`, `threat_techniques`.",
      "Mitigation & Prediction Logs: Relates `threat_mitigations` and `threat_predicted_steps` to parent threats."
    ],
    layout: "content"
  },
  {
    id: 25,
    section: "Implementation & Engineering",
    title: "Frontend & Interface Architecture",
    content: [
      "React Ecosystem: Built on React.js 18 and Vite for rapid, modular component development.",
      "Bold Design System: Implements a custom aesthetic prioritizing high-contrast and dynamic glassmorphism.",
      "Interactive Visualization: Uses Recharts and Framer Motion for metrics, animations, and complex cyber-art.",
      "Responsive Layouts: Optimized for analyst workstations to provide real-time dashboard feedback without latency."
    ],
    layout: "split",
    widget: "none"
  },
  {
    id: 26,
    section: "Implementation & Engineering",
    title: "Local Quantization & Inference Tuning",
    content: [
      "Model Quantization: Employs 4-bit quantization (Q4_K_M) on Phi-3.5-mini-instruct.",
      "Memory Footprint Reduction: Reduces model RAM requirements to fit within the local 8GB boundary.",
      "Inference Acceleration: Employs `llama_cpp` compiler flags targeting Apple Metal APIs."
    ],
    layout: "split",
    widget: "hardware"
  },
  {
    id: 27,
    section: "Implementation & Engineering",
    title: "Major Engineering Challenges Resolved",
    content: [
      "HTML Pipeline Dual-Schema: Parsed both Flexbox Summary and traditional Technical threat modeling reports.",
      "PCAP Memory Allocation: Implemented chunking and protocol-level stream parsing for files up to 100MB.",
      "API Rate-Limit Handling: Programmed seamless, real-time fallbacks to local engines."
    ],
    layout: "content"
  },

  // SECTION 5: RESULTS, TESTING & EVALUATION (Slides 28-35)
  {
    id: 28,
    section: "Results, Testing & Evaluation",
    title: "Testing Framework & IEEE 829 Standards",
    content: [
      "Test Plan Structure: Built according to the IEEE 829 Standard for Software Test Documentation.",
      "Coverage: Unit, integration, and quantitative AI evaluation scripts (`test_accuracy.py`).",
      "Test Case Execution: Executed 37 formal test cases (TC-01 through TC-37) achieving 100% PASS rate."
    ],
    layout: "content"
  },
  {
    id: 29,
    section: "Results, Testing & Evaluation",
    title: "AI Model Quantitative Accuracy",
    content: [
      "Rigorous Evaluation: Tested on a dataset of 20,736 cyber threat narratives across 499 ATT&CK techniques.",
      "Threat Mapping: Achieved 25.0% Precision, 46.0% Recall, and 32.4% F1-Score (Lenient Evaluation).",
      "Severity Classification: Reached 60.0% Accuracy in predicting CVSS-like impact levels."
    ],
    layout: "split",
    widget: "accuracy"
  },
  {
    id: 30,
    section: "Results, Testing & Evaluation",
    title: "System Performance & Latency Benchmarks",
    content: [
      "Groq Cloud Engine: Latency of ~0.8 seconds utilizing LPU-powered cloud inference.",
      "Local Fallback Engine: Latency of 4.0s - 6.5s running Phi-3.5-mini locally via Metal MPS.",
      "Usability Baseline: Both modes execute well within the NFR1 performance targets."
    ],
    layout: "split",
    widget: "latency"
  },
  {
    id: 31,
    section: "Results, Testing & Evaluation",
    title: "System Resiliency & Failover Validation",
    content: [
      "Failover Logic (TC-33): Artificially blocked cloud Groq API requests during runtime.",
      "Automatic Transition: Exception handler successfully redirected queries to local Phi-3.5-mini.",
      "Zero Downtime: Processed and mapped threat queues continuously with zero host memory crashes."
    ],
    layout: "content"
  },
  {
    id: 32,
    section: "Results, Testing & Evaluation",
    title: "Case Study: Threat Mapping Process",
    content: [
      "Raw Ingested Text: \"adversary uses Mimikatz to dump credential material from LSASS.\"",
      "SecureBERT Extraction: Identifies threat intent as credential dumping and LSASS access.",
      "Framework Mapping: maps to MITRE ATT&CK technique T1003 (OS Credential Dumping).",
      "Mitigation Output: Recommends D3FEND Credential Access protection and NIST AC-6 access controls."
    ],
    layout: "content"
  },
  {
    id: 33,
    section: "Results, Testing & Evaluation",
    title: "Interoperability: SIEM Integration",
    content: [
      "STIX 2.1 Export: Formats detected threat intelligence into structured JSON STIX objects.",
      "SIEM Compatibility: Validated importing generated reports into Splunk and Wazuh.",
      "Actionable Middleware: Seamlessly integrates design-time mapping with active SOC watchlists."
    ],
    layout: "split",
    widget: "stix_tree"
  },
  {
    id: 34,
    section: "Results, Testing & Evaluation",
    title: "Local Load & Scalability Benchmarks",
    content: [
      "Locust Load Testing: Evaluated backend REST API under simulated concurrent user traffic.",
      "Target Load: Successfully handled 20 concurrent analysts making concurrent upload requests.",
      "Degradation Rate: Latency increased linearly without causing server timeouts or connection drops."
    ],
    layout: "content"
  },
  {
    id: 35,
    section: "Results, Testing & Evaluation",
    title: "Database & Vector Storage Footprint",
    content: [
      "SQLite Optimization: Indexes on threat records and mappings maintain query speeds under 10ms.",
      "ChromaDB Footprint: Vector embeddings databases compress framework definitions to <50MB.",
      "API Cache: OSINT feeds and VirusTotal lookups are cached to avoid API rate limiting."
    ],
    layout: "content"
  },

  // SECTION 6: CONCLUSION & FUTURE WORK (Slides 36-40)
  {
    id: 36,
    section: "Conclusion & Future Work",
    title: "Academic & Practical Contributions",
    content: [
      "Unified Threat Pipeline: Bridges design threat modeling with real-time SOC incident detection.",
      "Optimized Edge AI: Demonstrates that domain-specific NLP models can run locally on constrained hardware.",
      "Hallucination Prevention: Validated the effectiveness of semantic RAG in grounding cybersecurity AI."
    ],
    layout: "content"
  },
  {
    id: 37,
    section: "Conclusion & Future Work",
    title: "Real-World Applications for Threat Hunters",
    content: [
      "Incident Triage: Accelerates classification of incoming security events.",
      "Vulnerability Mitigation: Instantly generates framework-aligned mitigation steps for dev teams.",
      "Reduced Analyst Burnout: Automates manual translation, reducing alert fatigue in modern SOCs."
    ],
    layout: "content"
  },
  {
    id: 38,
    section: "Conclusion & Future Work",
    title: "Unsupervised Anomaly Discovery",
    content: [
      "DBSCAN Clustering: Future feature leverages density-based spatial clustering of applications with noise.",
      "Novel Threat Detection: Clusters new anomalous logs that do not match existing MITRE signatures.",
      "Zero-Day Identification: Discovers emerging attack vectors before official security disclosures."
    ],
    layout: "split",
    widget: "dbscan"
  },
  {
    id: 39,
    section: "Conclusion & Future Work",
    title: "Future Enhancements & Extensions",
    content: [
      "Framework Expansion: Add Cloud Security Alliance (CSA) and regional standards (GDPR, ISO 27001).",
      "Local Model Tuning: Fine-tune local models to match cloud performance without memory overhead.",
      "Distributed Stream Processing: Upgrade the PCAP engine with Apache Spark for real-time traffic analysis."
    ],
    layout: "content"
  },
  {
    id: 40,
    section: "Conclusion & Future Work",
    title: "Conclusion & Q&A",
    content: [
      "autoMITRE: Successful B.Sc. Graduation Thesis in Cybersecurity.",
      "Eliminating manual bottlenecks to secure modern digital ecosystems.",
      "Thank you for your time. The floor is open for Questions & Answers."
    ],
    layout: "title"
  }
];
