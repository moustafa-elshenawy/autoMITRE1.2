import { motion } from 'framer-motion';

const events = [
  { t: 0, label: 'TC-33 Started', desc: 'Normal operation — Groq API serving requests', color: '#10b981', type: 'normal' },
  { t: 1, label: 'API Artificially Blocked', desc: 'Network exception injected at 45s mark', color: '#ef4444', type: 'failure' },
  { t: 2, label: 'Exception Caught', desc: 'ConnectionError detected in ai_threat_analyzer.py', color: '#f59e0b', type: 'warn' },
  { t: 3, label: 'Failover Triggered', desc: 'Redirecting to local Phi-3.5-mini via llama_cpp', color: '#f59e0b', type: 'warn' },
  { t: 4, label: 'Local Engine Active', desc: 'Metal MPS acceleration engaged — 4.2s latency', color: '#0ea5e9', type: 'recovery' },
  { t: 5, label: 'Threat Queue Cleared', desc: 'All 12 pending analyses completed — Zero crashes', color: '#10b981', type: 'success' },
];

export default function FailoverTest() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-2">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Resiliency Test TC-33 — Failover Validation</p>
      <div className="w-full relative">
        {/* Timeline bar */}
        <div className="absolute left-5 top-0 bottom-0 w-0.5 bg-slate-800" />
        <div className="flex flex-col gap-2 pl-10">
          {events.map((event, i) => (
            <motion.div
              key={event.t}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.3, duration: 0.4 }}
              className="relative flex items-start gap-2"
            >
              {/* Dot */}
              <motion.div
                animate={event.type === 'failure' ? { scale: [1, 1.5, 1] } : {}}
                transition={{ duration: 0.5, repeat: event.type === 'failure' ? 3 : 0, delay: i * 0.3 }}
                className="absolute -left-[29px] top-1 w-3 h-3 rounded-full border-2"
                style={{
                  backgroundColor: `${event.color}30`,
                  borderColor: event.color,
                  boxShadow: `0 0 6px ${event.color}60`,
                }}
              />
              <div className="flex-1 pb-1">
                <p className="text-[9px] font-bold font-mono" style={{ color: event.color }}>{event.label}</p>
                <p className="text-[7px] text-slate-400 font-mono">{event.desc}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2 }}
        className="flex items-center gap-2 bg-emerald-950/30 border border-emerald-700/40 rounded-xl px-3 py-1.5 w-full justify-center"
      >
        <span className="text-emerald-400 text-sm">✓</span>
        <p className="text-[9px] font-bold font-mono text-emerald-300">
          Result: PASS — Zero downtime • Zero memory crashes
        </p>
      </motion.div>
    </div>
  );
}
