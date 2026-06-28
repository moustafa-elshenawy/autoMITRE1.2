import { motion } from 'framer-motion';

const requirements = [
  { id: 'FR1', label: 'Auth & RBAC', test: 'TC-01 to TC-03', result: 'PASS', color: '#0ea5e9' },
  { id: 'FR2', label: 'Multi-Format Upload', test: 'TC-04 to TC-07', result: 'PASS', color: '#8b5cf6' },
  { id: 'FR3', label: 'AI Threat Analysis', test: 'TC-08 to TC-11', result: 'PASS', color: '#10b981' },
  { id: 'FR4', label: 'Framework Mapping', test: 'TC-12 to TC-13', result: 'PASS', color: '#f59e0b' },
  { id: 'FR5', label: 'Mitigation Gen', test: 'TC-14', result: 'PASS', color: '#ec4899' },
  { id: 'FR6', label: 'Threat Prediction', test: 'TC-15', result: 'PASS', color: '#06b6d4' },
  { id: 'FR7', label: 'Dashboard UI', test: 'TC-16', result: 'PASS', color: '#84cc16' },
  { id: 'FR8', label: 'PDF Export', test: 'TC-17', result: 'PASS', color: '#f97316' },
  { id: 'FR9', label: 'SIEM / STIX Export', test: 'TC-18', result: 'PASS', color: '#a855f7' },
];

export default function FRValidation() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-3">
      <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">Functional Requirements Validation</p>

      <div className="w-full flex flex-col gap-2.5 max-w-4xl mt-2">
        {requirements.map((req, i) => (
          <motion.div
            key={req.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.12, duration: 0.4 }}
            className="flex items-center gap-3"
          >
            <span
              className="w-10 text-[11px] font-bold font-mono text-center py-1 rounded shrink-0"
              style={{ color: req.color, backgroundColor: `${req.color}15` }}
            >
              {req.id}
            </span>
            <div className="flex-1 flex items-center gap-3 bg-slate-900/40 rounded-xl px-4 py-2.5 border border-slate-800/50">
              <span className="text-sm font-mono font-bold text-slate-200 flex-1">{req.label}</span>
              <span className="text-xs text-slate-400 font-mono bg-slate-800/40 px-2 py-0.5 rounded shrink-0">{req.test}</span>
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: i * 0.12 + 0.4, type: 'spring', bounce: 0.6 }}
                className="flex items-center gap-1.5 shrink-0"
              >
                <motion.div
                  animate={{ boxShadow: [`0 0 0px #10b981`, `0 0 10px #10b98180`, `0 0 0px #10b981`] }}
                  transition={{ duration: 2, repeat: Infinity, delay: i * 0.2 }}
                  className="w-4 h-4 rounded-full bg-emerald-500 flex items-center justify-center"
                >
                  <span className="text-[10px] text-white font-bold">✓</span>
                </motion.div>
                <span className="text-[11px] font-bold text-emerald-400 font-mono w-8">{req.result}</span>
              </motion.div>
            </div>
          </motion.div>
        ))}
      </div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.5 }}
        className="text-sm font-bold text-emerald-400 font-mono text-center mt-3"
      >
        9 / 9 Functional Requirements Validated ✓
      </motion.div>
    </div>
  );
}
