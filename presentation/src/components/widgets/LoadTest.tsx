import { motion } from 'framer-motion';

const concurrencyData = [1, 5, 10, 15, 20];
const latencyData = [0.8, 1.1, 1.9, 3.2, 5.1]; // seconds
const maxLatency = 6;

export default function LoadTest() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-3">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">Locust Load Test — 20 Concurrent Analysts</p>

      {/* Chart */}
      <div className="w-full flex flex-col gap-1">
        <div className="flex items-end gap-2 h-36 w-full">
          {concurrencyData.map((users, i) => (
            <div key={users} className="flex-1 flex flex-col items-center gap-1">
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.3 + i * 0.2 }}
                className="text-[8px] font-mono font-bold text-amber-400"
              >
                {latencyData[i]}s
              </motion.span>
              <motion.div
                initial={{ height: 0 }}
                animate={{ height: `${(latencyData[i] / maxLatency) * 100}%` }}
                transition={{ duration: 0.7, delay: 0.3 + i * 0.2, ease: [0.34, 1.56, 0.64, 1] }}
                className="w-full rounded-t-md"
                style={{
                  background: `linear-gradient(to top, rgba(6,182,212,0.8), rgba(139,92,246,0.6))`,
                  boxShadow: '0 0 8px rgba(6,182,212,0.4)',
                }}
              />
              <span className="text-[7px] text-slate-400 font-mono">{users} users</span>
            </div>
          ))}
        </div>
        {/* Axes */}
        <div className="flex justify-between text-[7px] font-mono text-slate-500 px-1">
          <span>← Concurrent Users →</span>
          <span>Latency (seconds) ↑</span>
        </div>
      </div>

      {/* Key insights */}
      <div className="w-full grid grid-cols-3 gap-1.5">
        {[
          { label: 'Max Users Tested', value: '20', color: '#06b6d4' },
          { label: 'No Timeouts', value: '0', color: '#10b981' },
          { label: 'Degradation', value: 'Linear', color: '#f59e0b' },
        ].map((stat) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1.3 }}
            className="bg-slate-900/50 border border-slate-800/50 rounded-lg p-2 text-center"
          >
            <p className="text-xs font-bold font-mono" style={{ color: stat.color }}>{stat.value}</p>
            <p className="text-[7px] text-slate-500 font-mono">{stat.label}</p>
          </motion.div>
        ))}
      </div>
      <p className="text-[8px] text-slate-500 font-mono text-center">
        Linear latency degradation with no server timeouts or connection drops
      </p>
    </div>
  );
}
