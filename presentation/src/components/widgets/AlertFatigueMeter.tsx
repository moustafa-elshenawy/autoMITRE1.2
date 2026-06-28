import { motion, useAnimationFrame } from 'framer-motion';
import { useRef, useState } from 'react';

const ALERT_TYPES = ['SQL Injection', 'Phishing URL', 'Port Scan', 'Brute Force', 'C2 Beacon', 'XSS Attempt', 'DDoS', 'Lateral Move', 'Priv Escalation', 'Zero-Day'];
const COLORS = ['#ef4444', '#f59e0b', '#8b5cf6', '#ec4899', '#0ea5e9'];

export default function AlertFatigueMeter() {
  const [count, setCount] = useState(0);
  const [alerts, setAlerts] = useState<{ id: number; type: string; color: string; x: number }[]>([]);
  const counterRef = useRef(0);
  const idRef = useRef(0);

  useAnimationFrame((t) => {
    const speed = Math.min(50, 1 + Math.floor(t / 1000));
    if (Math.floor(t / speed) !== Math.floor((t - 16) / speed)) {
      counterRef.current += 1;
      setCount(counterRef.current);
      if (counterRef.current < 200) {
        idRef.current++;
        setAlerts(prev => [...prev.slice(-30), {
          id: idRef.current,
          type: ALERT_TYPES[idRef.current % ALERT_TYPES.length],
          color: COLORS[idRef.current % COLORS.length],
          x: Math.random() * 85,
        }]);
      }
    }
  });

  const displayCount = Math.min(count * 52, 10000);

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-2 overflow-hidden">
      {/* Counter */}
      <motion.div className="text-center">
        <motion.div
          className="text-5xl font-bold font-mono"
          style={{ color: count > 100 ? '#ef4444' : '#f59e0b' }}
        >
          {displayCount.toLocaleString()}+
        </motion.div>
        <p className="text-xs text-slate-400 font-mono mt-1">alerts per day • 1 SOC analyst</p>
      </motion.div>

      {/* Alert stream */}
      <div className="relative w-full h-32 overflow-hidden rounded-lg border border-slate-800/50 bg-slate-950/50">
        {alerts.slice(-25).map((alert) => (
          <motion.div
            key={alert.id}
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 120, opacity: [0, 1, 1, 0] }}
            transition={{ duration: 2.5, ease: 'linear' }}
            className="absolute text-[9px] font-mono px-1 py-0.5 rounded whitespace-nowrap"
            style={{
              left: `${alert.x}%`,
              top: 0,
              color: alert.color,
              backgroundColor: `${alert.color}15`,
              border: `1px solid ${alert.color}40`,
            }}
          >
            ⚠ {alert.type}
          </motion.div>
        ))}
      </div>

      {/* Analyst stress indicator */}
      <div className="w-full flex items-center gap-2">
        <span className="text-xs text-slate-400 font-mono shrink-0">Analyst Capacity:</span>
        <div className="flex-grow h-2 rounded-full bg-slate-800 overflow-hidden">
          <motion.div
            animate={{ width: `${Math.min((count / 200) * 100, 100)}%` }}
            className="h-full rounded-full"
            style={{ background: 'linear-gradient(to right, #22c55e, #f59e0b, #ef4444)' }}
          />
        </div>
        <motion.span
          animate={{ color: count > 150 ? '#ef4444' : '#f59e0b' }}
          className="text-xs font-mono font-bold"
        >
          {count > 150 ? 'OVERLOADED' : count > 80 ? 'STRESSED' : 'MANAGING'}
        </motion.span>
      </div>
    </div>
  );
}
