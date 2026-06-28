import { motion } from 'framer-motion';

const data = [
  { year: '2019', attacks: 32, label: '32K' },
  { year: '2020', attacks: 48, label: '48K' },
  { year: '2021', attacks: 67, label: '67K' },
  { year: '2022', attacks: 84, label: '84K' },
  { year: '2023', attacks: 117, label: '117K' },
  { year: '2024', attacks: 158, label: '158K' },
  { year: '2025', attacks: 212, label: '212K' },
];

const maxVal = 212;

export default function ThreatSurge() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-3">
      <p className="text-sm text-cyan-400 font-mono uppercase tracking-widest mb-2">
        Global Cyber Incidents (Thousands/Year)
      </p>
      <div className="w-full flex items-end justify-around gap-2 h-48">
        {data.map((d, i) => (
          <div key={d.year} className="flex flex-col items-center gap-1 flex-1">
            <motion.span
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 + i * 0.15, duration: 0.4 }}
              className="text-sm font-mono font-bold text-red-400"
            >
              {d.label}
            </motion.span>
            <motion.div
              initial={{ height: 0 }}
              animate={{ height: `${(d.attacks / maxVal) * 100}%` }}
              transition={{ duration: 0.7, delay: i * 0.12, ease: [0.34, 1.56, 0.64, 1] }}
              className="w-full rounded-t-md relative overflow-hidden"
              style={{
                background: `linear-gradient(to top, rgba(239,68,68,0.9), rgba(251,146,60,0.7))`,
                boxShadow: '0 0 12px rgba(239,68,68,0.5)',
              }}
            >
              <motion.div
                animate={{ opacity: [0.4, 0.9, 0.4] }}
                transition={{ duration: 2, repeat: Infinity, delay: i * 0.2 }}
                className="absolute inset-0 bg-gradient-to-t from-transparent to-red-300/20"
              />
            </motion.div>
            <span className="text-xs text-slate-400 font-mono mt-1">{d.year}</span>
          </div>
        ))}
      </div>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
        className="flex items-center gap-2 mt-2"
      >
        <motion.div
          animate={{ scale: [1, 1.3, 1] }}
          transition={{ duration: 1, repeat: Infinity }}
          className="w-2 h-2 rounded-full bg-red-500"
        />
        <span className="text-sm text-red-400 font-mono">+562% surge since 2019 — defenses haven't kept pace</span>
      </motion.div>
    </div>
  );
}
