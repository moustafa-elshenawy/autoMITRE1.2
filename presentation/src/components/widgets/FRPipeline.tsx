import { motion } from 'framer-motion';

const frs = [
  { id: 'FR1', label: 'Auth & RBAC', color: '#64748b', priority: 'MEDIUM' },
  { id: 'FR2', label: 'Input Upload', color: '#0ea5e9', priority: 'HIGH' },
  { id: 'FR3', label: 'AI Analysis', color: '#8b5cf6', priority: 'HIGH' },
  { id: 'FR4', label: 'Framework Map', color: '#10b981', priority: 'HIGH' },
  { id: 'FR5', label: 'Mitigation Gen', color: '#f59e0b', priority: 'HIGH' },
  { id: 'FR6', label: 'Threat Predict', color: '#ec4899', priority: 'HIGH' },
  { id: 'FR7', label: 'Dashboard', color: '#06b6d4', priority: 'HIGH' },
  { id: 'FR8', label: 'PDF Export', color: '#84cc16', priority: 'MEDIUM' },
  { id: 'FR9', label: 'SIEM Export', color: '#f97316', priority: 'HIGH' },
];

export default function FRPipeline() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-3">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Functional Requirements Pipeline (IEEE 830)</p>
      <div className="relative w-full">
        {/* Pipeline line */}
        <motion.div
          initial={{ scaleX: 0 }}
          animate={{ scaleX: 1 }}
          transition={{ duration: 1.2, delay: 0.3 }}
          className="absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-slate-700 via-cyan-600/50 to-slate-700 origin-left"
          style={{ transform: 'translateY(-50%)' }}
        />
        <div className="flex justify-between items-center relative">
          {frs.map((fr, i) => (
            <div key={fr.id} className="flex flex-col items-center gap-1">
              <motion.span
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.5 + i * 0.12 }}
                className="text-[7px] font-mono font-bold"
                style={{ color: fr.priority === 'HIGH' ? '#fbbf24' : '#64748b' }}
              >
                {fr.priority}
              </motion.span>
              <motion.div
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: 0.4 + i * 0.12, type: 'spring', bounce: 0.5 }}
                className="w-10 h-10 rounded-full border-2 flex items-center justify-center relative z-10"
                style={{ borderColor: fr.color, backgroundColor: `${fr.color}15` }}
              >
                <motion.div
                  animate={{ boxShadow: [`0 0 0px ${fr.color}`, `0 0 10px ${fr.color}60`, `0 0 0px ${fr.color}`] }}
                  transition={{ duration: 2, repeat: Infinity, delay: i * 0.2 }}
                  className="w-full h-full rounded-full flex items-center justify-center"
                >
                  <span className="text-[8px] font-bold font-mono" style={{ color: fr.color }}>{fr.id}</span>
                </motion.div>
              </motion.div>
              <motion.span
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.6 + i * 0.12 }}
                className="text-[7px] text-slate-400 font-mono text-center"
                style={{ maxWidth: '42px' }}
              >
                {fr.label}
              </motion.span>
            </div>
          ))}
        </div>
      </div>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.8 }}
        className="text-center"
      >
        <span className="text-[9px] text-slate-500 font-mono">9 Functional Requirements • 6 HIGH priority • All validated (100% PASS)</span>
      </motion.div>
    </div>
  );
}
