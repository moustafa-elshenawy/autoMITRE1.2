import { motion } from 'framer-motion';

const layers = [
  {
    label: 'INPUT LAYER',
    color: '#0ea5e9',
    items: ['Text', 'JSON', 'HTML', 'PCAP', 'CSV', 'Hash'],
  },
  {
    label: 'AI ENGINE',
    color: '#8b5cf6',
    items: ['SecureBERT', 'RAG/ChromaDB', 'LLM (Groq)', 'Local Phi-3.5'],
  },
  {
    label: 'MAPPING LAYER',
    color: '#10b981',
    items: ['ATT&CK', 'D3FEND', 'NIST 800-53', 'OWASP ASVS'],
  },
  {
    label: 'OUTPUT LAYER',
    color: '#f59e0b',
    items: ['Dashboard', 'STIX 2.1', 'JSON Export', 'Mitigations'],
  },
];

export default function ArchOverview() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-2">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">System Architecture — 4 Layers</p>
      <div className="w-full flex flex-col gap-2">
        {layers.map((layer, li) => (
          <motion.div
            key={layer.label}
            initial={{ opacity: 0, x: -40, scaleX: 0.7 }}
            animate={{ opacity: 1, x: 0, scaleX: 1 }}
            transition={{ delay: li * 0.25, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
            className="flex items-center gap-3 rounded-xl border p-2"
            style={{ borderColor: `${layer.color}40`, backgroundColor: `${layer.color}08` }}
          >
            <div
              className="text-[8px] font-mono font-bold w-20 shrink-0 text-center py-1 rounded-lg"
              style={{ color: layer.color, backgroundColor: `${layer.color}15`, border: `1px solid ${layer.color}40` }}
            >
              {layer.label}
            </div>
            <div className="flex gap-1.5 flex-wrap">
              {layer.items.map((item, ii) => (
                <motion.span
                  key={item}
                  initial={{ opacity: 0, scale: 0.5 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: li * 0.25 + ii * 0.08 + 0.3, type: 'spring' }}
                  className="text-[8px] font-mono px-2 py-0.5 rounded-md"
                  style={{ color: layer.color, backgroundColor: `${layer.color}15`, border: `1px solid ${layer.color}30` }}
                >
                  {item}
                </motion.span>
              ))}
            </div>
            {li < layers.length - 1 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: li * 0.25 + 0.6 }}
                className="ml-auto shrink-0"
                style={{ color: layer.color }}
              >
                ↓
              </motion.div>
            )}
          </motion.div>
        ))}
      </div>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
        className="text-[9px] text-slate-500 font-mono"
      >
        FastAPI (Backend) ↔ React.js (Frontend) ↔ SQLite + ChromaDB (Storage)
      </motion.div>
    </div>
  );
}
