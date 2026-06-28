import { motion } from 'framer-motion';
import { Shield } from 'lucide-react';

const stats = [
  { label: 'Accuracy', value: '96.81%', color: '#10b981' },
  { label: 'Test Cases', value: '37 PASS', color: '#0ea5e9' },
  { label: 'Frameworks', value: '4 Mapped', color: '#8b5cf6' },
  { label: 'Latency', value: '0.8s', color: '#f59e0b' },
  { label: 'Inputs', value: '7 Formats', color: '#ec4899' },
  { label: 'SIEM Ready', value: 'STIX 2.1', color: '#06b6d4' },
];

// Shield segments
const TOTAL = 6;

export default function ConclusionShield() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-4">
      <div className="flex gap-6 items-center">
        {/* Shield assembling */}
        <div className="relative w-36 h-36 flex items-center justify-center">
          {stats.map((stat, i) => {
            const angle = (i / TOTAL) * 360;
            const rad = (angle * Math.PI) / 180;
            const x = Math.cos(rad - Math.PI / 2) * 52;
            const y = Math.sin(rad - Math.PI / 2) * 52;
            return (
              <motion.div
                key={stat.label}
                initial={{ x, y, opacity: 0, scale: 0 }}
                animate={{ x: x * 0.2, y: y * 0.2, opacity: 0.8, scale: 0.6 }}
                transition={{ delay: i * 0.2 + 0.3, duration: 0.6, type: 'spring' }}
                className="absolute"
              >
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: stat.color }} />
              </motion.div>
            );
          })}

          <motion.div
            initial={{ opacity: 0, scale: 0, rotate: -180 }}
            animate={{ opacity: 1, scale: 1, rotate: 0 }}
            transition={{ delay: 1.5, duration: 0.8, type: 'spring', bounce: 0.4 }}
          >
            <motion.div
              animate={{ boxShadow: ['0 0 20px rgba(34,211,238,0.3)', '0 0 40px rgba(34,211,238,0.6)', '0 0 20px rgba(34,211,238,0.3)'] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <Shield className="w-24 h-24 text-cyan-400" strokeWidth={1} />
            </motion.div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 2 }}
            className="absolute"
          >
            <p className="text-[9px] font-bold font-mono text-cyan-300 text-center leading-tight">auto<br />MITRE</p>
          </motion.div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-2">
          {stats.map((stat, i) => (
            <motion.div
              key={stat.label}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.5 + i * 0.15, duration: 0.4 }}
              className="flex flex-col items-center p-2 rounded-xl border text-center"
              style={{ borderColor: `${stat.color}40`, backgroundColor: `${stat.color}08` }}
            >
              <motion.span
                animate={{ color: [stat.color, '#ffffff', stat.color] }}
                transition={{ duration: 3, repeat: Infinity, delay: i * 0.4 }}
                className="text-base font-bold font-mono"
              >
                {stat.value}
              </motion.span>
              <span className="text-[7px] text-slate-400 font-mono">{stat.label}</span>
            </motion.div>
          ))}
        </div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 2.2 }}
        className="text-center"
      >
        <p className="text-sm font-bold text-slate-200 font-mono">autoMITRE — Mission Accomplished</p>
        <p className="text-[9px] text-slate-400 font-mono mt-1">
          Bridging static threat modeling with AI-driven active defense automation
        </p>
      </motion.div>
    </div>
  );
}
