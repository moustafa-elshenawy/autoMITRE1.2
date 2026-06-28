import { motion } from 'framer-motion';

const phases = [
  {
    phase: 'Phase 1',
    label: 'Fine-tune Local Models',
    desc: 'Match cloud accuracy without memory overhead',
    color: '#0ea5e9',
    quarter: 'Q3 2026',
  },
  {
    phase: 'Phase 2',
    label: 'Cloud Security Alliance',
    desc: 'Add CSA, ISO 27001, GDPR framework mappings',
    color: '#8b5cf6',
    quarter: 'Q4 2026',
  },
  {
    phase: 'Phase 3',
    label: 'Apache Spark PCAP Engine',
    desc: 'Distributed stream processing for real-time traffic',
    color: '#10b981',
    quarter: 'Q1 2027',
  },
  {
    phase: 'Phase 4',
    label: 'Enterprise Deployment',
    desc: 'SIEM live integration, Auth hardening, SaaS delivery',
    color: '#f59e0b',
    quarter: 'Q2 2027',
  },
];

export default function FutureRoadmap() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-6">
      <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">Future Enhancement Roadmap</p>

      {/* Timeline */}
      <div className="w-full relative max-w-5xl mt-2">
        {/* Bar */}
        <motion.div
          initial={{ scaleX: 0 }}
          animate={{ scaleX: 1 }}
          transition={{ duration: 1.2, delay: 0.3 }}
          className="absolute top-7 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500/50 via-purple-500/50 to-amber-500/50 origin-left"
        />

        <div className="flex justify-between items-start gap-4">
          {phases.map((p, i) => (
            <div key={p.phase} className="flex flex-col items-center gap-3 flex-1">
              {/* Quarter label */}
              <motion.span
                initial={{ opacity: 0, y: -5 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 + i * 0.2 }}
                className="text-[11px] font-mono font-bold text-slate-400"
              >
                {p.quarter}
              </motion.span>

              {/* Node */}
              <motion.div
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: 0.7 + i * 0.2, type: 'spring' }}
                className="w-5 h-5 rounded-full border-[2.5px] z-10 relative"
                style={{ borderColor: p.color, backgroundColor: `${p.color}20` }}
              >
                <motion.div
                  animate={{ scale: [1, 1.6, 1], opacity: [0.5, 0, 0.5] }}
                  transition={{ duration: 2, repeat: Infinity, delay: i * 0.5 }}
                  className="absolute inset-0 rounded-full"
                  style={{ backgroundColor: p.color }}
                />
              </motion.div>

              {/* Card */}
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.9 + i * 0.2 }}
                className="rounded-xl border p-3.5 text-center w-full"
                style={{ borderColor: `${p.color}40`, backgroundColor: `${p.color}08` }}
              >
                <p className="text-[11px] font-bold font-mono" style={{ color: p.color }}>{p.phase}</p>
                <p className="text-xs font-bold text-slate-200 mt-1">{p.label}</p>
                <p className="text-[10px] text-slate-400 mt-1 leading-snug">{p.desc}</p>
              </motion.div>
            </div>
          ))}
        </div>
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.8 }}
        className="text-[11px] text-slate-500 font-mono text-center mt-4"
      >
        DBSCAN zero-day clustering • Federated SIEM integrations • Production hardening
      </motion.p>
    </div>
  );
}
