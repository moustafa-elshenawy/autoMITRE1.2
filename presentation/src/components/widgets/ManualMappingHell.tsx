import { motion } from 'framer-motion';
import { User, ArrowRight, Clock, AlertCircle } from 'lucide-react';

const steps = [
  { label: 'Raw Threat Log', color: '#64748b', icon: '📄' },
  { label: 'Analyst Reads', color: '#f59e0b', icon: '👤' },
  { label: 'Manual Lookup', color: '#f59e0b', icon: '🔍' },
  { label: 'MITRE Search', color: '#8b5cf6', icon: '📚' },
  { label: 'Cross-Reference', color: '#ef4444', icon: '🔄' },
  { label: 'Map Technique', color: '#10b981', icon: '✅' },
];

export default function ManualMappingHell() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-4">
      {/* Flow chain */}
      <div className="flex items-center gap-1 flex-wrap justify-center">
        {steps.map((step, i) => (
          <div key={step.label} className="flex items-center gap-1">
            <motion.div
              initial={{ opacity: 0, scale: 0.5 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.3, duration: 0.4, type: 'spring' }}
              className="flex flex-col items-center gap-1"
            >
              <motion.div
                animate={i > 0 && i < 5 ? { borderColor: ['#f59e0b50', '#ef444450', '#f59e0b50'] } : {}}
                transition={{ duration: 1.5, repeat: Infinity }}
                className="w-14 h-14 rounded-xl border flex flex-col items-center justify-center"
                style={{ borderColor: `${step.color}50`, backgroundColor: `${step.color}10` }}
              >
                <span className="text-xl">{step.icon}</span>
              </motion.div>
              <span className="text-[8px] font-mono text-center text-slate-400 w-16">{step.label}</span>
            </motion.div>
            {i < steps.length - 1 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.3 + 0.5 }}
              >
                <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
              </motion.div>
            )}
          </div>
        ))}
      </div>

      {/* Time cost indicator */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 2.0 }}
        className="flex items-center gap-4 bg-red-950/30 border border-red-800/40 rounded-xl px-4 py-2 w-full"
      >
        <Clock className="w-4 h-4 text-red-400 shrink-0" />
        <div>
          <p className="text-xs font-bold text-red-300">Avg. time per manual mapping: <span className="text-red-400">15–40 minutes</span></p>
          <p className="text-[10px] text-slate-500 mt-0.5">Per analyst • Per incident • While attackers move in seconds</p>
        </div>
        <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
      </motion.div>

      {/* AutoMITRE contrast */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 2.5 }}
        className="flex items-center gap-4 bg-emerald-950/30 border border-emerald-800/40 rounded-xl px-4 py-2 w-full"
      >
        <motion.div
          animate={{ rotate: [0, 360] }}
          transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
          className="w-4 h-4 border-2 border-emerald-400 border-t-transparent rounded-full shrink-0"
        />
        <p className="text-xs font-bold text-emerald-300">autoMITRE: same mapping in <span className="text-emerald-400">&lt; 1.2 seconds</span> automatically</p>
      </motion.div>
    </div>
  );
}
