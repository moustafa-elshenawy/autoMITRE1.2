import { motion } from 'framer-motion';

const tools = [
  {
    name: 'Microsoft TMT',
    strength: 'STRIDE methodology',
    gap: 'Static — no runtime analysis',
    color: '#0ea5e9',
    icon: '🏗️',
  },
  {
    name: 'OWASP Threat Dragon',
    strength: 'Open-source, diagram-first',
    gap: 'Manual — relies on human input',
    color: '#6366f1',
    icon: '🐉',
  },
  {
    name: 'VirusTotal / OSINT',
    strength: 'Signature detection',
    gap: 'No MITRE T-Code mapping',
    color: '#f59e0b',
    icon: '🔎',
  },
];

export default function LitReviewLayer() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center gap-4 p-3">
      {/* autoMITRE top layer */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.4, duration: 0.6, type: 'spring' }}
        className="w-full max-w-sm rounded-xl border-2 border-amber-400/70 bg-amber-500/10 px-4 py-2 flex items-center justify-between"
        style={{ boxShadow: '0 0 20px rgba(251,191,36,0.25)' }}
      >
        <div className="flex items-center gap-2">
          <span className="text-xl">🛡️</span>
          <div>
            <p className="text-amber-400 font-bold font-mono text-sm tracking-wide">autoMITRE</p>
            <p className="text-[10px] text-amber-300/70 font-mono">Enhancement &amp; Integration Layer</p>
          </div>
        </div>
        <motion.div
          animate={{ scale: [1, 1.15, 1] }}
          transition={{ duration: 1.5, repeat: Infinity }}
          className="text-[10px] font-mono bg-amber-400/20 text-amber-400 px-2 py-0.5 rounded-full border border-amber-400/40"
        >
          AI-Powered
        </motion.div>
      </motion.div>

      {/* Connectors */}
      <div className="flex w-full max-w-sm justify-around h-6 relative">
        {tools.map((_, i) => (
          <motion.div
            key={i}
            className="flex flex-col items-center"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.0 + i * 0.1 }}
          >
            <motion.div
              animate={{ opacity: [0.3, 1, 0.3] }}
              transition={{ duration: 1.4, repeat: Infinity, delay: i * 0.2 }}
              className="w-0.5 h-full bg-gradient-to-b from-amber-400/70 to-transparent"
            />
            <span className="text-[8px] text-amber-400 font-mono mt-0.5">▲</span>
          </motion.div>
        ))}
        <p className="absolute top-1 right-0 text-[8px] font-mono text-slate-500">integrates &amp; enhances</p>
      </div>

      {/* Tool cards */}
      <div className="flex gap-2 w-full">
        {tools.map((t, i) => (
          <motion.div
            key={t.name}
            initial={{ opacity: 0, y: 20, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ delay: i * 0.2, duration: 0.5, type: 'spring' }}
            className="flex-1 rounded-xl border p-2.5 flex flex-col gap-1.5"
            style={{ borderColor: `${t.color}50`, backgroundColor: `${t.color}0D` }}
          >
            <div className="flex items-center gap-1.5">
              <span className="text-base">{t.icon}</span>
              <p className="text-[10px] font-bold font-mono text-slate-200 leading-tight">{t.name}</p>
            </div>
            <div className="flex items-center gap-1">
              <span className="text-[9px]">✅</span>
              <p className="text-[9px] font-mono leading-tight" style={{ color: t.color }}>{t.strength}</p>
            </div>
            <div className="flex items-start gap-1">
              <span className="text-[9px] mt-0.5">❌</span>
              <p className="text-[9px] text-red-400/80 font-mono leading-tight">{t.gap}</p>
            </div>
          </motion.div>
        ))}
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2.0 }}
        className="text-[9px] text-slate-500 font-mono text-center"
      >
        autoMITRE does not replace these tools — it completes what they cannot do alone
      </motion.p>
    </div>
  );
}
