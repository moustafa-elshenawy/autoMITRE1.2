import { motion } from 'framer-motion';

const frameworks = [
  { name: 'MITRE ATT&CK', sub: 'T1003.001 — Credential Dump', color: '#ef4444', accuracy: '84.06%' },
  { name: 'MITRE D3FEND', sub: 'Process Isolation',            color: '#8b5cf6', accuracy: '98.41%' },
  { name: 'NIST 800-53',  sub: 'AC-6, SC-28',                  color: '#0ea5e9', accuracy: '98.41%' },
  { name: 'OWASP ASVS',  sub: 'V2.6.1',                        color: '#10b981', accuracy: '~90%'   },
];

export default function FrameworkMapper() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-6">
      <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">
        Multi-Framework Mapping Engine
      </p>

      {/* Central threat */}
      <motion.div
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.5, type: 'spring' }}
        className="bg-gradient-to-br from-amber-900/50 to-orange-900/50 border-2 border-amber-500/60 rounded-xl px-8 py-4 text-center"
        style={{ boxShadow: '0 0 24px rgba(251,191,36,0.3)' }}
      >
        <p className="text-[11px] font-mono text-amber-300 uppercase tracking-widest">Detected Threat</p>
        <p className="text-lg font-bold text-amber-400 font-mono mt-1.5">Credential Dumping</p>
        <p className="text-[11px] text-slate-400 font-mono mt-1">LSASS Memory Access</p>
      </motion.div>

      {/* Framework fan-out */}
      <div className="grid grid-cols-2 gap-3 w-full max-w-4xl">
        {frameworks.map((fw, i) => (
          <motion.div
            key={fw.name}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 + i * 0.2, duration: 0.4 }}
            className="rounded-xl border p-3.5 flex items-center gap-3"
            style={{ borderColor: `${fw.color}40`, backgroundColor: `${fw.color}08` }}
          >
            <motion.div
              animate={{ opacity: [1, 0.4, 1] }}
              transition={{ duration: 2, repeat: Infinity, delay: i * 0.5 }}
              className="w-4 h-4 rounded-full shrink-0"
              style={{ backgroundColor: fw.color }}
            />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-bold font-mono" style={{ color: fw.color }}>{fw.name}</p>
              <p className="text-[10px] font-mono text-slate-400 truncate mt-0.5">{fw.sub}</p>
            </div>
            <span className="text-sm font-mono font-bold shrink-0" style={{ color: fw.color }}>
              {fw.accuracy}
            </span>
          </motion.div>
        ))}
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.8 }}
        className="text-[11px] text-slate-500 font-mono text-center mt-2"
      >
        Cosine similarity matching • Semantic embedding alignment • All 4 frameworks in one pass
      </motion.p>
    </div>
  );
}
