export type SlideWidget = 'latency' | 'accuracy' | 'architecture' | 'simulator' | 'none';

export type SlideData = {
  id: number;
  section: string;
  title: string;
  content: string[];
  widget?: SlideWidget;
  layout?: 'title' | 'content' | 'split';
};

export const slides: SlideData[] = [
  // 1. TITLE & ACKNOWLEDGEMENTS (Slides 1-3)
  {
    id: 1,
    section: "Title",
    title: "AutoMITRE: AI-Powered Threat Modeling and SOC Automation",
    content: [
      "Revolutionizing Cybersecurity Defenses via Generative AI",
      "Automated TTP Extraction & Interactive Visualization"
    ],
    layout: "title"
  },
  {
    id: 2,
    section: "Acknowledgements",
    title: "Project Authors",
    content: [
      "Moustafa Ahmed Elsayed Elshenawy",
      "Abd El-Rahman Mohammed Abd-Eltawab",
      "Hashem Abdo Hashem",
      "Mira Amin",
      "Jana Wael",
      "Jomana Mohsen"
    ],
    layout: "content"
  },
  {
    id: 3,
    section: "Acknowledgements",
    title: "Academic Supervision",
    content: [
      "Supervisor: Dr. Ahmed Maher",
      "Arab Academy for Science, Technology, and Maritime Transport (AASTMT)",
      "College of Computing and Information Technology"
    ],
    layout: "content"
  },

  // 2. INTRODUCTION (Slides 4-8)
  {
    id: 4,
    section: "Introduction",
    title: "The Static Modeling Gap",
    content: [
      "Traditional threat modeling relies on static, point-in-time assessments.",
      "Security Operations Centers (SOCs) face highly dynamic, rapidly evolving environments.",
      "The gap between static models and active defense leads to missed vulnerabilities."
    ],
    layout: "content"
  },
  {
    id: 5,
    section: "Introduction",
    title: "The Manual Parsing Burden",
    content: [
      "Cyber Threat Intelligence (CTI) is predominantly shared in unstructured text formats.",
      "Analysts spend excessive hours manually parsing narratives, reports, and raw logs.",
      "This process is highly error-prone and unscalable against massive data influxes."
    ],
    layout: "content"
  },
  {
    id: 6,
    section: "Introduction",
    title: "Project Objectives",
    content: [
      "Automate the ingestion and parsing of heterogeneous threat data.",
      "Eliminate manual mapping by directly linking intelligence to the MITRE ATT&CK framework.",
      "Provide a highly visual, interactive dashboard for instantaneous threat comprehension."
    ],
    layout: "content"
  },
  {
    id: 7,
    section: "Introduction",
    title: "Scope of AutoMITRE",
    content: [
      "Targeted at automating SOC Level 1/2 analytical tasks.",
      "Focuses exclusively on the MITRE ATT&CK Enterprise Matrix.",
      "Handles multiple data modalities: Raw Text, PCAP, IriusRisk HTML, OSINT."
    ],
    layout: "content"
  },
  {
    id: 8,
    section: "Introduction",
    title: "The Vision",
    content: [
      "\"From raw unstructured data to actionable, mapped intelligence in seconds, not hours.\"",
      "A proactive defense posture powered by local, privacy-preserving AI engines."
    ],
    layout: "content"
  },

  // 3. PROBLEM STATEMENT (Slides 9-13)
  {
    id: 9,
    section: "Problem Statement",
    title: "SIEM Ingestion Limitations",
    content: [
      "Modern SIEMs (Splunk, Sentinel) excel at log aggregation but struggle with unstructured narrative ingestion.",
      "Lack of semantic understanding leads to poorly categorized security alerts.",
      "High volume of false positives due to rigid deterministic matching rules."
    ],
    layout: "split",
    widget: "siem_funnel"
  },
  {
    id: 10,
    section: "Problem Statement",
    title: "MITRE ATT&CK Complexity",
    content: [
      "The framework contains hundreds of specific Techniques and Sub-Techniques.",
      "Manual mapping requires deep domain expertise and constant framework memorization.",
      "Contextual nuance is easily lost when mapping complex attack chains manually."
    ],
    layout: "content"
  },
  {
    id: 11,
    section: "Problem Statement",
    title: "API Rate Limits & Privacy",
    content: [
      "Relying purely on external APIs (e.g., OpenAI) introduces severe privacy risks.",
      "Uploading sensitive network data (PCAP) or internal architectures is a compliance violation.",
      "Strict API rate limits throttle continuous, real-time threat analysis pipelines."
    ],
    layout: "content"
  },
  {
    id: 12,
    section: "Problem Statement",
    title: "Hardware Constraints",
    content: [
      "Running 70B parameter models locally requires multiple high-end GPUs.",
      "Most SOC analyst workstations lack the memory (VRAM) to load massive models.",
      "AutoMITRE employs quantization to fit local fallback models (like Phi-3.5) into standard hardware."
    ],
    layout: "split",
    widget: "hardware"
  },
  {
    id: 13,
    section: "Problem Statement",
    title: "The Threat Landscape Reality",
    content: [
      "Threat actors automate their attacks; defenders must automate their analysis.",
      "Speed is the critical metric in SOC environments to reduce the Mean Time To Respond (MTTR)."
    ],
    layout: "content"
  },

  // 4. RELATED WORK (Slides 14-18)
  {
    id: 14,
    section: "Related Work",
    title: "Deterministic vs Generative",
    content: [
      "Existing tools utilize Regex and simple keyword matching (Deterministic).",
      "Deterministic models fail spectacularly on obfuscated or newly phrased threats.",
      "Generative AI provides the required semantic reasoning to map novel attacks."
    ],
    layout: "content"
  },
  {
    id: 15,
    section: "Related Work",
    title: "The Pitfalls of AI Hallucinations",
    content: [
      "Generative LLMs are prone to hallucinating non-existent ATT&CK techniques.",
      "A raw LLM might predict \"T9999: Memory Exfiltration\" which does not exist.",
      "AutoMITRE's RAG architecture forces the LLM to ground its output in actual ChromaDB retrieved documents, drastically reducing false positives."
    ],
    layout: "split",
    widget: "guardrail"
  },
  {
    id: 16,
    section: "Related Work",
    title: "Need for Local NLP Models",
    content: [
      "Previous attempts utilized massive cloud infrastructure, incurring high costs.",
      "AutoMITRE introduces highly quantized (Q4_K_M) local models via llama.cpp.",
      "Provides military-grade privacy by keeping all inference local."
    ],
    layout: "content"
  },
  {
    id: 17,
    section: "Related Work",
    title: "Current Threat Modeler Constraints",
    content: [
      "Tools like IriusRisk generate excellent PDF/HTML reports, but they are static.",
      "No direct pipeline exists to map IriusRisk outputs dynamically to SIEM watchlists.",
      "AutoMITRE acts as the bridge via its dual-schema HTML parser."
    ],
    layout: "content"
  },
  {
    id: 18,
    section: "Related Work",
    title: "Advancements in Embeddings",
    content: [
      "SecureBERT: A domain-specific language model pre-trained on massive cybersecurity text.",
      "Outperforms general-purpose embeddings (like text-embedding-ada-002) in isolating cyber semantics.",
      "Serves as AutoMITRE's primary classification backbone."
    ],
    layout: "content"
  },

  // 5. PROPOSED SYSTEM ARCHITECTURE (Slides 19-26)
  {
    id: 19,
    section: "Architecture",
    title: "High-Level System Design",
    content: [
      "A fully decoupled, modern architecture built for scalability and local execution."
    ],
    widget: "architecture",
    layout: "split"
  },
  {
    id: 20,
    section: "Architecture",
    title: "FastAPI Backend",
    content: [
      "High-performance Python backend serving concurrent analytical pipelines.",
      "Handles heavy computational loads, model loading, and asynchronous processing.",
      "Strict Pydantic schemas enforce type-safe data boundaries."
    ],
    layout: "content"
  },
  {
    id: 21,
    section: "Architecture",
    title: "React Frontend",
    content: [
      "Vite-powered Single Page Application (SPA) offering a real-time dashboard.",
      "Highly responsive interface built with Tailwind CSS and Framer Motion.",
      "Visualizes data immediately as it streams from the analytical pipelines."
    ],
    layout: "content"
  },
  {
    id: 22,
    section: "Architecture",
    title: "The Intake Router",
    content: [
      "Dynamic data ingestion layer capable of parsing multiple modalities:",
      "- Raw Text & Narratives",
      "- Complex IriusRisk HTML Layouts",
      "- Network Traffic (PCAP)",
      "- Open Source Intelligence (OSINT)"
    ],
    layout: "split",
    widget: "intake"
  },
  {
    id: 23,
    section: "Architecture",
    title: "Hybrid AI Engine",
    content: [
      "AutoMITRE uses a tiered intelligence approach to maximize speed and privacy.",
      "Primary: Groq Cloud API (Llama-3.1-8B / Llama-3.3-70B) for ultra-fast, zero-memory inference.",
      "Fallback: Local hardware-accelerated LLM for offline privacy."
    ],
    layout: "content"
  },
  {
    id: 24,
    section: "Architecture",
    title: "Offline Fallback & Hardware Accel.",
    content: [
      "Utilizes Apple Metal (MPS) acceleration via llama_cpp.",
      "Runs quantized Phi-3.5-mini entirely on local 8GB RAM.",
      "Seamlessly takes over if the Groq API throttles or internet connectivity drops."
    ],
    layout: "content"
  },
  {
    id: 25,
    section: "Architecture",
    title: "ChromaDB & RAG",
    content: [
      "Local vector database (ChromaDB) stores the entire MITRE ATT&CK framework.",
      "Retrieval-Augmented Generation ensures LLM outputs are explicitly grounded in verified MITRE IDs.",
      "Completely eliminates LLM hallucinations."
    ],
    layout: "content"
  },
  {
    id: 26,
    section: "Architecture",
    title: "Threat Mapping Simulator",
    content: [
      "Interactive demonstration of the semantic mapping algorithm."
    ],
    widget: "simulator",
    layout: "split"
  },

  // 6. IMPLEMENTATION & RESULTS (Slides 27-34)
  {
    id: 27,
    section: "Results",
    title: "Inference Latency Comparison",
    content: [
      "Benchmarking the Hybrid Architecture: Cloud vs Local execution times."
    ],
    widget: "latency",
    layout: "split"
  },
  {
    id: 28,
    section: "Results",
    title: "Latency Analysis",
    content: [
      "Groq Cloud API achieves near-instantaneous 0.8s inference via LPUs.",
      "Local Metal Fallback maintains functional usability at 4.0s - 6.5s.",
      "Demonstrates successful operation on highly constrained analyst hardware."
    ],
    layout: "content"
  },
  {
    id: 29,
    section: "Results",
    title: "Accuracy Metrics",
    content: [
      "Evaluating the deterministic success of the SecureBERT models."
    ],
    widget: "accuracy",
    layout: "split"
  },
  {
    id: 30,
    section: "Results",
    title: "Metric Breakdown",
    content: [
      "SecureBERT F1-Score: 96.65% across distinct cyber datasets.",
      "Threat Severity Scoring: 95.22% accuracy in predicting CVSS-like impact.",
      "Framework Mapping: 98.41% success rate in exact MITRE ID correlation."
    ],
    layout: "content"
  },
  {
    id: 31,
    section: "Results",
    title: "Handling Massive PCAP Data",
    content: [
      "Tested against massive 150MB+ network packet capture files.",
      "The system successfully chunks, streams, and prevents Out-of-Memory (OOM) kernel panics.",
      "Efficient boundary parsing extracts only relevant HTTP/TCP streams."
    ],
    layout: "content"
  },
  {
    id: 32,
    section: "Results",
    title: "API Timeout Triggers",
    content: [
      "Robust exception handling proven during extensive end-to-end (E2E) testing.",
      "When external APIs trigger a 429 Too Many Requests, the system pivots to the local model instantly.",
      "Zero downtime during aggressive threat ingestion."
    ],
    layout: "content"
  },
  {
    id: 33,
    section: "Results",
    title: "Interoperability (STIX 2.1)",
    content: [
      "All generated threat models are actively exported to the STIX 2.1 schema.",
      "Successfully ingested into external Splunk instances during integration testing.",
      "Ensures AutoMITRE is a viable middleware for enterprise SOCs."
    ],
    layout: "split",
    widget: "stix_tree"
  },
  {
    id: 34,
    section: "Results",
    title: "Maintainability & Scale",
    content: [
      "Decoupled pipeline architecture allows \"hot-swapping\" models without breaking the core engine.",
      "New data modalities can be added simply by subclassing the BasePipeline interface."
    ],
    layout: "content"
  },

  // 7. CONCLUSION & FUTURE WORK (Slides 35-40)
  {
    id: 35,
    section: "Conclusion",
    title: "Total Threat Processing",
    content: [
      "AutoMITRE successfully processed over 20,736 distinct threat narratives during validation.",
      "Proved the viability of hybrid cloud/local AI architectures in privacy-critical domains.",
      "Bridged the gap between unstructured data and automated SOC ingestion."
    ],
    layout: "content"
  },
  {
    id: 36,
    section: "Future Work",
    title: "Advanced Clustering (DBSCAN)",
    content: [
      "Implementing DBSCAN algorithms to detect entirely novel, unseen attack campaigns based on embedding distances.",
      "Moving beyond classification to active threat discovery."
    ],
    layout: "split",
    widget: "dbscan"
  },
  {
    id: 37,
    section: "Future Work",
    title: "Expanding Frameworks",
    content: [
      "Integrating the Cloud Security Alliance (CSA) matrices.",
      "Adding D3FEND framework mapping to provide automated mitigation strategies alongside threat detection."
    ],
    layout: "content"
  },
  {
    id: 38,
    section: "Future Work",
    title: "Distributed Data Processing",
    content: [
      "Upgrading the PCAP parsing engine to leverage Apache Spark.",
      "Enabling the processing of multi-gigabyte enterprise traffic captures in real-time."
    ],
    layout: "content"
  },
  {
    id: 39,
    section: "Conclusion",
    title: "Final Summary",
    content: [
      "AutoMITRE represents a paradigm shift in threat intelligence.",
      "By combining modern web stacks, optimized LLMs, and deterministic vector searches, we eliminate the manual mapping bottleneck."
    ],
    layout: "content"
  },
  {
    id: 40,
    section: "Q&A",
    title: "Questions & Answers",
    content: [
      "Thank you for your time and attention.",
      "We are now open for any questions regarding the AutoMITRE architecture, results, or implementation details."
    ],
    layout: "title"
  }
];
