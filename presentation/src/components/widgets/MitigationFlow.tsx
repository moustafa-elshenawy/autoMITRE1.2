import { motion } from 'framer-motion';

const steps = [
  { n: '01', label: 'Detect', desc: 'AI identifies threat behavior from input', color: '#0ea5e9', icon: '🔍' },
  { n: '02', label: 'Map', desc: 'Correlate to ATT&CK + D3FEND + NIST', color: '#8b5cf6', icon: '🗺' },
  { n: '03', label: 'Reason', desc: 'LLM generates explainable context', color: '#f59e0b', icon: '🧠' },
  { n: '04', label: 'Recommend', desc: 'Step-by-step mitigation action plan', color: '#10b981', icon: '✅' },
];

export default function MitigationFlow() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-4">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Mitigation Generation — 4-Stage Pipeline</p>
      <div className="flex w-full items-center gap-0 relative">
        {/* Connecting bar */}
        <motion.div
          initial={{ scaleX: 0 }}
          animate={{ scaleX: 1 }}
          transition={{ duration: 1, delay: 0.5 }}
          className="absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-500/50 via-purple-500/50 via-amber-500/50 to-emerald-500/50 origin-left"
          style={{ transform: 'translateY(-200%)' }}
        />

        {steps.map((step, i) => (
          <div key={step.n} className="flex items-center flex-1">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.2 + 0.3, type: 'spring' }}
              className="flex-1 flex flex-col items-center gap-2"
            >
              <motion.div
                animate={{ boxShadow: [`0 0 0px ${step.color}`, `0 0 15px ${step.color}60`, `0 0 0px ${step.color}`] }}
                transition={{ duration: 2, repeat: Infinity, delay: i * 0.5 }}
                className="w-14 h-14 rounded-2xl border-2 flex flex-col items-center justify-center gap-0.5"
                style={{ borderColor: step.color, backgroundColor: `${step.color}10` }}
              >
                <span className="text-xl">{step.icon}</span>
                <span className="text-[7px] font-mono font-bold" style={{ color: step.color }}>{step.n}</span>
              </motion.div>
              <div className="text-center">
                <p className="text-[10px] font-bold font-mono" style={{ color: step.color }}>{step.label}</p>
                <p className="text-[7px] text-slate-400 mt-0.5 leading-tight">{step.desc}</p>
              </div>
            </motion.div>
            {i < steps.length - 1 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.2 + 0.7 }}
                className="text-slate-600 text-sm shrink-0 -mt-6"
              >
                →
              </motion.div>
            )}
          </div>
        ))}
      </div>

      {/* Example output */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.5 }}
        className="w-full bg-emerald-950/30 border border-emerald-800/40 rounded-xl p-2"
      >
        <p className="text-[8px] font-mono text-emerald-400 font-bold mb-1">Example Mitigation Output:</p>
        <p className="text-[7px] font-mono text-slate-300 leading-relaxed">
          1. Enable LSASS process protection (Windows Credential Guard) [NIST AC-6]<br />
          2. Block Mimikatz signatures at endpoint [D3FEND: Software-based Process Isolation]<br />
          3. Enable Privileged Access Workstations (PAW) for domain admins [NIST SC-28]
        </p>
      </motion.div>
    </div>
  );
}
