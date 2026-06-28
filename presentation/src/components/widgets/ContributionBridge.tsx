import { motion } from 'framer-motion';

const leftTools = [
  'Microsoft TMT', 'IriusRisk', 'OWASP Dragon',
  'Raw Threat Description', 'Network PCAP', 'Logs / CSV', 'JSON / STIX',
];
const rightOutputs = ['ATT&CK Map', 'D3FEND Plan', 'NIST Controls', 'STIX Export', 'Mitigations'];

export default function ContributionBridge() {
  return (
    <div className="w-full h-full flex items-center justify-center p-4">
      <div className="w-full flex items-center gap-0">
        {/* Left: Fragmented inputs */}
        <div className="flex flex-col gap-1 w-5/12">
          {leftTools.map((tool, i) => (
            <motion.div
              key={tool}
              initial={{ opacity: 0, x: -30 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.08, duration: 0.4 }}
              className="bg-cyan-950/30 border border-cyan-700/40 rounded px-3 py-1.5 text-center"
            >
              <span className="text-[12px] font-mono text-slate-400">{tool}</span>
            </motion.div>
          ))}
        </div>

        {/* Bridge */}
        <div className="flex-grow flex flex-col items-center justify-center relative h-44">
          <svg className="absolute inset-0 w-full h-full" viewBox="0 0 60 100" preserveAspectRatio="none">
            {leftTools.map((_, i) => {
              const y1 = 5 + i * 9.5;
              return (
                <motion.path
                  key={i}
                  d={`M 0 ${y1} Q 30 50 60 ${35 + (i % 5) * 8}`}
                  fill="none"
                  stroke={`rgba(34,211,238,${0.2 + (i % 5) * 0.08})`}
                  strokeWidth="0.6"
                  initial={{ pathLength: 0, opacity: 0 }}
                  animate={{ pathLength: 1, opacity: 1 }}
                  transition={{ delay: 0.5 + i * 0.08, duration: 0.6 }}
                />
              );
            })}
          </svg>

          <motion.div
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 1.8, type: 'spring', bounce: 0.5 }}
            className="relative z-10 bg-gradient-to-br from-cyan-900/60 to-emerald-900/60 border-2 border-cyan-500/60 rounded-xl px-3 py-2 text-center"
            style={{ boxShadow: '0 0 20px rgba(34,211,238,0.3)' }}
          >
            <motion.div
              animate={{ boxShadow: ['0 0 10px rgba(34,211,238,0.3)', '0 0 25px rgba(34,211,238,0.6)', '0 0 10px rgba(34,211,238,0.3)'] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <p className="text-[14px] font-bold text-cyan-300 font-mono">autoMITRE</p>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">AI Unification</p>
            </motion.div>
          </motion.div>
        </div>

        {/* Right: Unified outputs */}
        <div className="flex flex-col gap-1 w-5/12">
          {rightOutputs.map((out, i) => (
            <motion.div
              key={out}
              initial={{ opacity: 0, x: 30 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 1.5 + i * 0.12, duration: 0.4 }}
              className="bg-emerald-950/40 border border-emerald-700/50 rounded px-3 py-1.5 text-center"
            >
              <span className="text-[12px] font-mono text-emerald-300">✓ {out}</span>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}
