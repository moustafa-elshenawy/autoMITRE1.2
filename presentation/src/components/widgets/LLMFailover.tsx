import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';

export default function LLMFailover() {
  const [phase, setPhase] = useState(0);
  // 0=normal, 1=blocked, 2=failover, 3=local_success
  useEffect(() => {
    const timings = [2000, 3500, 5000, 6500];
    const ids = timings.map((t, i) => setTimeout(() => setPhase(i + 1), t));
    const reset = setTimeout(() => setPhase(0), 9000);
    return () => { ids.forEach(clearTimeout); clearTimeout(reset); };
  }, []);

  // restart
  useEffect(() => {
    if (phase === 0) {
      const id = setTimeout(() => {}, 100);
      return () => clearTimeout(id);
    }
  }, [phase]);

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-4">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Cloud + Local Failover Architecture</p>

      <div className="w-full flex flex-col gap-2">
        {/* Primary path */}
        <div className="flex items-center gap-2">
          <motion.div
            animate={{ borderColor: phase >= 1 ? '#ef4444' : '#10b981', backgroundColor: phase >= 1 ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)' }}
            className="flex-1 p-2 rounded-xl border text-center"
          >
            <p className="text-[9px] font-mono font-bold text-slate-300">☁ Groq Cloud API</p>
            <p className="text-[8px] font-mono text-slate-400">LPU-powered • ~0.8s latency</p>
          </motion.div>
          <motion.div
            animate={{ width: phase >= 1 ? '60px' : '80px' }}
            className="h-1 rounded-full"
            style={{ background: phase >= 1 ? '#ef4444' : '#10b981' }}
          />
          <motion.div
            animate={{ opacity: phase >= 1 ? 1 : 0 }}
            className="w-16 h-8 rounded-lg bg-red-950/40 border border-red-600/60 flex items-center justify-center"
          >
            <span className="text-[8px] text-red-400 font-mono">BLOCKED</span>
          </motion.div>
        </div>

        {/* Status label */}
        <motion.div
          animate={{ opacity: phase >= 1 ? 1 : 0 }}
          className="text-center"
        >
          <motion.span
            animate={{ color: phase === 1 ? '#ef4444' : phase === 2 ? '#f59e0b' : '#10b981' }}
            className="text-[9px] font-mono font-bold"
          >
            {phase === 1 ? '⚠ Groq API Unavailable — Initiating Failover...' :
             phase === 2 ? '🔄 Redirecting to Local Engine...' :
             phase >= 3 ? '✓ Local Phi-3.5-mini Active — Zero Downtime' : ''}
          </motion.span>
        </motion.div>

        {/* Failover path */}
        <motion.div
          animate={{ opacity: phase >= 2 ? 1 : 0.2, borderColor: phase >= 3 ? '#10b981' : '#f59e0b50' }}
          className="flex items-center gap-2 p-2 rounded-xl border bg-slate-900/40"
        >
          <span className="text-xl">💻</span>
          <div className="flex-1">
            <p className="text-[9px] font-mono font-bold text-slate-300">Local Engine: Phi-3.5-mini</p>
            <p className="text-[8px] font-mono text-slate-400">4-bit quantized (Q4_K_M) • Apple Metal MPS • 4–6.5s latency</p>
          </div>
          <motion.div
            animate={{ opacity: phase >= 3 ? 1 : 0 }}
            className="flex items-center gap-1"
          >
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[8px] text-emerald-400 font-mono">ACTIVE</span>
          </motion.div>
        </motion.div>

        {/* Hardware specs */}
        <motion.div
          animate={{ opacity: phase >= 3 ? 1 : 0 }}
          className="grid grid-cols-3 gap-1"
        >
          {[['Platform', 'Apple M1'], ['RAM', '8GB constraint'], ['Acceleration', 'Metal MPS']].map(([k, v]) => (
            <div key={k} className="bg-slate-900/60 rounded-lg p-1.5 text-center border border-slate-800/50">
              <p className="text-[7px] text-slate-500 font-mono">{k}</p>
              <p className="text-[8px] text-emerald-300 font-mono font-bold">{v}</p>
            </div>
          ))}
        </motion.div>
      </div>
    </div>
  );
}
