import { motion } from 'framer-motion';

const layers = [
  { label: 'Input Embedding', nodes: 8, color: '#64748b' },
  { label: 'Transformer Layer 1', nodes: 6, color: '#0ea5e9' },
  { label: 'Transformer Layer 2', nodes: 6, color: '#8b5cf6' },
  { label: 'Attention Head', nodes: 4, color: '#10b981' },
  { label: 'Classification', nodes: 3, color: '#f59e0b' },
];

const metrics = [
  { label: 'Overall Accuracy', value: 96.81, color: '#10b981' },
  { label: 'F1-Score', value: 96.65, color: '#0ea5e9' },
  { label: 'Severity Acc.', value: 95.22, color: '#8b5cf6' },
];

export default function SecureBERTBrain() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-6 gap-6">
      <p className="text-sm font-mono text-slate-400 uppercase tracking-widest">SecureBERT — Cybersecurity-Tuned Transformer</p>
      <div className="flex gap-8 w-full items-center justify-center">
        {/* Neural network visual */}
        <div className="flex items-center gap-3 flex-1">
          {layers.map((layer, li) => (
            <div key={layer.label} className="flex flex-col gap-2 items-center flex-1">
              {Array.from({ length: layer.nodes }).map((_, ni) => (
                <motion.div
                  key={ni}
                  initial={{ scale: 0, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: li * 0.15 + ni * 0.04, type: 'spring' }}
                  className="w-5 h-5 rounded-full"
                  style={{ backgroundColor: `${layer.color}30`, border: `2px solid ${layer.color}70` }}
                >
                  <motion.div
                    animate={{ opacity: [0.3, 1, 0.3] }}
                    transition={{ duration: 1.5 + ni * 0.3, repeat: Infinity, delay: li * 0.3 + ni * 0.2 }}
                    className="w-full h-full rounded-full"
                    style={{ backgroundColor: layer.color }}
                  />
                </motion.div>
              ))}
              <span className="text-[9px] font-bold font-mono text-slate-400 text-center mt-2 leading-tight"
                style={{ maxWidth: '40px', wordBreak: 'break-word' }}>
                {layer.label}
              </span>
            </div>
          ))}
        </div>

        {/* Metrics */}
        <div className="flex flex-col gap-4 w-2/5 pl-4">
          {metrics.map((m, i) => (
            <motion.div
              key={m.label}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.8 + i * 0.2 }}
              className="flex flex-col gap-1.5"
            >
              <div className="flex justify-between items-center">
                <span className="text-xs font-mono text-slate-300 font-bold">{m.label}</span>
                <span className="text-sm font-bold font-mono" style={{ color: m.color }}>{m.value}%</span>
              </div>
              <div className="h-3 rounded-full bg-slate-800 overflow-hidden shadow-inner">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${m.value}%` }}
                  transition={{ delay: 1 + i * 0.2, duration: 0.8 }}
                  className="h-full rounded-full"
                  style={{ background: `linear-gradient(to right, ${m.color}80, ${m.color})` }}
                />
              </div>
            </motion.div>
          ))}
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.8 }}
            className="text-[10px] text-slate-500 font-mono mt-4 leading-relaxed"
          >
            Trained on cybersecurity corpora • Pre-trained by Hugging Face
          </motion.p>
        </div>
      </div>
    </div>
  );
}
