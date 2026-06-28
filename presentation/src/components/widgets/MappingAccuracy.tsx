import { motion } from 'framer-motion';

const mappings = [
  { label: 'ATT&CK Technique\nMapping', value: 84.06, color: '#ef4444', total: 499, desc: '499 techniques tested' },
  { label: 'D3FEND + NIST\nMapping', value: 98.41, color: '#8b5cf6', total: 100, desc: 'Deterministic mapping' },
];

const r = 42;
const circumference = 2 * Math.PI * r;

export default function MappingAccuracy() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-5">
      <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">Framework Mapping Accuracy</p>

      <div className="flex gap-10 items-center justify-center w-full">
        {mappings.map((m) => {
          const dash = (m.value / 100) * circumference;
          return (
            <motion.div
              key={m.label}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, type: 'spring' }}
              className="flex flex-col items-center gap-3"
            >
              <div className="relative w-36 h-36">
                <svg className="w-full h-full -rotate-90" viewBox="0 0 104 104">
                  <circle cx={52} cy={52} r={r} fill="none" stroke="#1e293b" strokeWidth={10} />
                  <motion.circle
                    cx={52} cy={52} r={r}
                    fill="none"
                    stroke={m.color}
                    strokeWidth={10}
                    strokeLinecap="round"
                    strokeDasharray={`${circumference}`}
                    initial={{ strokeDashoffset: circumference }}
                    animate={{ strokeDashoffset: circumference - dash }}
                    transition={{ duration: 1.2, delay: 0.5, ease: 'easeOut' }}
                    style={{ filter: `drop-shadow(0 0 6px ${m.color}80)` }}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 1.0 }}
                    className="text-2xl font-bold font-mono"
                    style={{ color: m.color }}
                  >
                    {m.value}%
                  </motion.span>
                </div>
              </div>
              <div className="text-center">
                {m.label.split('\n').map((line, i) => (
                  <p key={i} className="text-sm font-mono font-bold leading-tight" style={{ color: m.color }}>{line}</p>
                ))}
                <p className="text-[11px] text-slate-500 font-mono mt-1.5">{m.desc}</p>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Note */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
        className="w-full max-w-2xl bg-slate-900/50 border border-slate-800/50 rounded-xl p-3 mt-2"
      >
        <p className="text-[11px] font-mono text-slate-400 text-center leading-relaxed">
          ATT&CK semantic matching uses cosine similarity (harder problem — 499 unique techniques)<br />
          D3FEND/NIST uses deterministic framework rule mapping (near-perfect coverage)
        </p>
      </motion.div>
    </div>
  );
}
