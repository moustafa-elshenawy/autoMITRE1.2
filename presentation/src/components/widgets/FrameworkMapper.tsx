import { motion } from 'framer-motion';

const frameworks = [
  { name: 'MITRE ATT&CK', sub: 'T1003.001 — Credential Dump', color: '#ef4444', accuracy: '84.06%' },
  { name: 'MITRE D3FEND', sub: 'Process Isolation',            color: '#8b5cf6', accuracy: '98.41%' },
  { name: 'NIST 800-53',  sub: 'AC-6, SC-28',                  color: '#0ea5e9', accuracy: '98.41%' },
  { name: 'OWASP ASVS',  sub: 'V2.6.1',                        color: '#10b981', accuracy: '~90%'   },
];

export default function FrameworkMapper() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-4">
      <p className="text-[11px] font-mono text-slate-400 uppercase tracking-widest">
        Multi-Framework Mapping Engine
      </p>

      {/* Central threat */}
      <motion.div
        initial={{ scale: 0, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.5, type: 'spring' }}
        className="bg-gradient-to-br from-amber-900/50 to-orange-900/50 border-2 border-amber-500/60 rounded-xl px-6 py-3 text-center"
        style={{ boxShadow: '0 0 20px rgba(251,191,36,0.3)' }}
      >
        <p className="text-[10px] font-mono text-amber-300 uppercase tracking-widest">Detected Threat</p>
        <p className="text-[14px] font-bold text-amber-400 font-mono mt-1">Credential Dumping</p>
        <p className="text-[10px] text-slate-400 font-mono mt-0.5">LSASS Memory Access</p>
      </motion.div>

      {/* Framework fan-out */}
      <div className="grid grid-cols-2 gap-2.5 w-full">
        {frameworks.map((fw, i) => (
          <motion.div
            key={fw.name}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 + i * 0.2, duration: 0.4 }}
            className="rounded-xl border p-2.5 flex items-center gap-2.5"
            style={{ borderColor: `${fw.color}40`, backgroundColor: `${fw.color}08` }}
          >
            <motion.div
              animate={{ opacity: [1, 0.4, 1] }}
              transition={{ duration: 2, repeat: Infinity, delay: i * 0.5 }}
              className="w-3 h-3 rounded-full shrink-0"
              style={{ backgroundColor: fw.color }}
            />
            <div className="flex-1 min-w-0">
              <p className="text-[11px] font-bold font-mono" style={{ color: fw.color }}>{fw.name}</p>
              <p className="text-[9px] font-mono text-slate-400 truncate mt-0.5">{fw.sub}</p>
            </div>
            <span className="text-[11px] font-mono font-bold shrink-0" style={{ color: fw.color }}>
              {fw.accuracy}
            </span>
          </motion.div>
        ))}
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.8 }}
        className="text-[9px] text-slate-500 font-mono text-center"
      >
        Cosine similarity matching • Semantic embedding alignment • All 4 frameworks in one pass
      </motion.p>
    </div>
  );
}
