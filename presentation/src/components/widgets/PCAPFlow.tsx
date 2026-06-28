import { motion, useAnimationFrame } from 'framer-motion';
import { useRef, useState } from 'react';

const PACKET_TYPES = [
  { label: 'TCP SYN', color: '#0ea5e9', suspicious: false },
  { label: 'DNS Query', color: '#10b981', suspicious: false },
  { label: 'C2 Beacon', color: '#ef4444', suspicious: true },
  { label: 'UDP Flood', color: '#f59e0b', suspicious: true },
  { label: 'ICMP Echo', color: '#8b5cf6', suspicious: false },
  { label: 'Port Scan', color: '#ec4899', suspicious: true },
];

export default function PCAPFlow() {
  const [packets, setPackets] = useState<{ id: number; type: typeof PACKET_TYPES[0]; x: number; progress: number }[]>([]);
  const [anomalies, setAnomalies] = useState(0);
  const timeRef = useRef(0);
  const idRef = useRef(0);

  useAnimationFrame((t, dt) => {
    timeRef.current += dt;
    if (timeRef.current > 600) {
      timeRef.current = 0;
      const type = PACKET_TYPES[Math.floor(Math.random() * PACKET_TYPES.length)];
      idRef.current++;
      setPackets(prev => {
        const next = [...prev.map(p => ({ ...p, progress: p.progress + 0.08 })).filter(p => p.progress < 1.1),
          { id: idRef.current, type, x: Math.random() * 60 + 20, progress: 0 }];
        return next.slice(-12);
      });
      if (type.suspicious) setAnomalies(a => Math.min(a + 1, 99));
    }
  });

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-2">
      <p className="text-[12px] font-mono text-slate-400 uppercase tracking-widest mb-2">PCAP Stream Analysis — Scapy Pipeline</p>

      {/* Stream visualization */}
      <div className="w-full h-32 relative rounded-xl border border-slate-800/50 bg-slate-950/60 overflow-hidden">
        {/* Network flow lanes */}
        {[0.25, 0.5, 0.75].map(y => (
          <div key={y} className="absolute left-0 right-0 border-t border-slate-800/30" style={{ top: `${y * 100}%` }} />
        ))}

        {/* Packets */}
        {packets.map(p => (
          <motion.div
            key={p.id}
            className="absolute text-[10px] font-mono px-2 py-1 rounded whitespace-nowrap"
            style={{
              left: `${p.x}%`,
              top: `${p.progress * 85}%`,
              color: p.type.color,
              backgroundColor: `${p.type.color}20`,
              border: `1px solid ${p.type.color}50`,
              boxShadow: p.type.suspicious ? `0 0 8px ${p.type.color}60` : 'none',
            }}
            animate={{ opacity: p.progress > 0.9 ? 0 : 1 }}
          >
            {p.type.suspicious && '⚠ '}{p.type.label}
          </motion.div>
        ))}
      </div>

      {/* Feature extraction */}
      <div className="w-full grid grid-cols-3 gap-1.5">
        {['Src/Dst IPs', 'Protocol Flags', 'Packet Timing', 'Payload Size', 'Port Numbers', 'Flow Duration'].map((feat, i) => (
          <motion.div
            key={feat}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: i * 0.15 + 0.5 }}
            className="text-[11px] font-mono text-slate-400 bg-slate-900/50 rounded px-3 py-1.5 border border-slate-800/50 text-center"
          >
            📊 {feat}
          </motion.div>
        ))}
      </div>

      {/* Anomaly counter */}
      <div className="w-full flex items-center justify-center gap-3 mt-2">
        <span className="text-[12px] text-slate-400 font-mono">Detected Anomalies:</span>
        <motion.span
          animate={{ color: anomalies > 30 ? '#ef4444' : '#f59e0b' }}
          className="text-xl font-bold font-mono"
        >
          {anomalies}
        </motion.span>
      </div>
    </div>
  );
}
