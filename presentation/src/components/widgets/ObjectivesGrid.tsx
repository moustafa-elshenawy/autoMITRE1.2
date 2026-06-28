import { motion } from 'framer-motion';

const objectives = [
  { icon: '📥', title: 'Multi-Format Ingestion', desc: 'PCAP, Text, JSON, HTML, CSV, Hashes', color: '#0ea5e9' },
  { icon: '🧠', title: 'AI Semantic Analysis', desc: 'SecureBERT + RAG-grounded reasoning', color: '#8b5cf6' },
  { icon: '🗺️', title: 'Framework Mapping', desc: 'ATT&CK, D3FEND, NIST 800-53, OWASP', color: '#10b981' },
  { icon: '🛡️', title: 'Mitigation Generation', desc: 'Explainable step-by-step defenses', color: '#f59e0b' },
  { icon: '🔮', title: 'Threat Prediction', desc: 'Next-stage attack forecasting via history', color: '#ec4899' },
  { icon: '🔗', title: 'SIEM Orchestration', desc: 'STIX 2.1 & JSON export for Splunk/Wazuh', color: '#06b6d4' },
];

export default function ObjectivesGrid() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-2">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">6 Core Objectives</p>
      <div className="grid grid-cols-3 gap-2 w-full">
        {objectives.map((obj, i) => (
          <motion.div
            key={obj.title}
            initial={{ opacity: 0, y: 20, scale: 0.8 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ delay: i * 0.15, duration: 0.5, type: 'spring' }}
            whileHover={{ scale: 1.05, y: -2 }}
            className="flex flex-col items-center gap-1.5 p-2.5 rounded-xl border text-center cursor-default"
            style={{ borderColor: `${obj.color}40`, backgroundColor: `${obj.color}0D` }}
          >
            <motion.span
              animate={{ scale: [1, 1.2, 1] }}
              transition={{ duration: 2, repeat: Infinity, delay: i * 0.3 }}
              className="text-2xl"
            >
              {obj.icon}
            </motion.span>
            <p className="text-[9px] font-bold font-mono" style={{ color: obj.color }}>{obj.title}</p>
            <p className="text-[8px] text-slate-500 leading-tight">{obj.desc}</p>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
