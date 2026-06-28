import { motion } from 'framer-motion';

const steps = [
  { n: '01', label: 'Detect',    desc: 'AI identifies threat behavior from input',        color: '#0ea5e9', icon: '🔍' },
  { n: '02', label: 'Map',       desc: 'Correlate to ATT&CK + D3FEND + NIST',             color: '#8b5cf6', icon: '🗺️' },
  { n: '03', label: 'Reason',    desc: 'LLM generates explainable context',                color: '#f59e0b', icon: '🧠' },
  { n: '04', label: 'Recommend', desc: 'Step-by-step mitigation action plan',              color: '#10b981', icon: '✅' },
];

export default function MitigationFlow() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-4">
      <p className="text-[11px] font-mono text-slate-400 uppercase tracking-widest">
        Mitigation Generation — 4-Stage Pipeline
      </p>

      <div className="flex w-full items-start gap-1 relative">
        {steps.map((step, i) => (
          <div key={step.n} className="flex items-center flex-1">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.2 + 0.3, type: 'spring' }}
              className="flex-1 flex flex-col items-center gap-2"
            >
              <motion.div
                animate={{ boxShadow: [`0 0 0px ${step.color}`, `0 0 18px ${step.color}70`, `0 0 0px ${step.color}`] }}
                transition={{ duration: 2, repeat: Infinity, delay: i * 0.5 }}
                className="w-16 h-16 rounded-2xl border-2 flex flex-col items-center justify-center gap-1"
                style={{ borderColor: step.color, backgroundColor: `${step.color}12` }}
              >
                <span className="text-2xl">{step.icon}</span>
                <span className="text-[9px] font-mono font-bold" style={{ color: step.color }}>{step.n}</span>
              </motion.div>
              <div className="text-center px-1">
                <p className="text-[12px] font-bold font-mono" style={{ color: step.color }}>{step.label}</p>
                <p className="text-[9px] text-slate-400 mt-0.5 leading-snug">{step.desc}</p>
              </div>
            </motion.div>

            {i < steps.length - 1 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.2 + 0.7 }}
                className="text-slate-500 text-lg shrink-0 -mt-8"
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
        className="w-full bg-emerald-950/30 border border-emerald-800/40 rounded-xl p-3"
      >
        <p className="text-[10px] font-mono text-emerald-400 font-bold mb-1.5">Example Mitigation Output:</p>
        <p className="text-[9.5px] font-mono text-slate-300 leading-relaxed">
          1. Enable LSASS process protection (Windows Credential Guard) [NIST AC-6]<br />
          2. Block Mimikatz signatures at endpoint [D3FEND: Software-based Process Isolation]<br />
          3. Enable Privileged Access Workstations (PAW) for domain admins [NIST SC-28]
        </p>
      </motion.div>
    </div>
  );
}
