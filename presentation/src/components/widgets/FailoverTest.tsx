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
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-4">
      <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">Resiliency Test TC-33 — Failover Validation</p>

      <div className="w-full relative max-w-4xl mt-2">
        {/* Timeline bar */}
        <div className="absolute left-6 top-1 bottom-1 w-0.5 bg-slate-800" />
        <div className="flex flex-col gap-3 pl-12">
          {events.map((event, i) => (
            <motion.div
              key={event.t}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.3, duration: 0.4 }}
              className="relative flex items-center gap-3"
            >
              {/* Dot */}
              <motion.div
                animate={event.type === 'failure' ? { scale: [1, 1.6, 1] } : {}}
                transition={{ duration: 0.5, repeat: event.type === 'failure' ? 3 : 0, delay: i * 0.3 }}
                className="absolute -left-[32px] top-1/2 -translate-y-1/2 w-4 h-4 rounded-full border-[2.5px]"
                style={{
                  backgroundColor: `${event.color}30`,
                  borderColor: event.color,
                  boxShadow: `0 0 10px ${event.color}60`,
                }}
              />
              <div className="flex-1 pb-1">
                <p className="text-sm font-bold font-mono" style={{ color: event.color }}>{event.label}</p>
                <p className="text-xs text-slate-400 font-mono mt-0.5">{event.desc}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2 }}
        className="flex items-center gap-3 bg-emerald-950/30 border border-emerald-700/40 rounded-xl px-5 py-3 w-full max-w-4xl justify-center mt-3"
      >
        <span className="text-emerald-400 text-2xl font-bold">✓</span>
        <p className="text-sm font-bold font-mono text-emerald-300">
          Result: PASS — Zero downtime • Zero memory crashes
        </p>
      </motion.div>
    </div>
  );
}
