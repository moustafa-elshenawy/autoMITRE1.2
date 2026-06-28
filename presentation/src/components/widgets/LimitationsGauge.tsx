import { motion } from 'framer-motion';

const gauges = [
  { label: 'PCAP Heuristic Accuracy', value: 63.2, max: 100, color: '#f59e0b', note: 'Behavioral baseline only' },
  { label: 'RAM Budget (M1 Local)', value: 78, max: 100, color: '#ef4444', note: '~6.2 GB / 8 GB used' },
  { label: 'API Rate Limits', value: 55, max: 100, color: '#f97316', note: 'Groq free tier constraints' },
  { label: 'Production Readiness', value: 65, max: 100, color: '#8b5cf6', note: 'Prototype stage — not deployed' },
];

export default function LimitationsGauge() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-3">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Honest Limitations Assessment</p>
      <div className="w-full flex flex-col gap-3">
        {gauges.map((g, i) => (
          <motion.div
            key={g.label}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.2 }}
            className="flex flex-col gap-1"
          >
            <div className="flex justify-between items-center">
              <span className="text-[9px] font-mono font-bold text-slate-300">{g.label}</span>
              <div className="flex items-center gap-1.5">
                <span className="text-[9px] font-bold font-mono" style={{ color: g.color }}>{g.value}%</span>
                <span className="text-[7px] text-slate-500 font-mono">({g.note})</span>
              </div>
            </div>
            <div className="h-3 rounded-full bg-slate-800 overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${g.value}%` }}
                transition={{ duration: 0.8, delay: i * 0.2 + 0.3, ease: 'easeOut' }}
                className="h-full rounded-full relative overflow-hidden"
                style={{ background: `linear-gradient(to right, ${g.color}60, ${g.color})` }}
              >
                <motion.div
                  animate={{ x: ['-100%', '200%'] }}
                  transition={{ duration: 2, repeat: Infinity, ease: 'linear', delay: i * 0.5 }}
                  className="absolute inset-y-0 w-1/3 bg-gradient-to-r from-transparent via-white/20 to-transparent"
                />
              </motion.div>
            </div>
          </motion.div>
        ))}
      </div>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
        className="text-[8px] text-slate-500 font-mono text-center"
      >
        Limitations are documented honestly per academic project scope — future work addresses each
      </motion.div>
    </div>
  );
}
