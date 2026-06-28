import { motion } from 'framer-motion';

const nfrs = [
  { label: 'Performance\n(NFR1)', value: 90, color: '#0ea5e9' },
  { label: 'Availability\n(NFR2)', value: 85, color: '#10b981' },
  { label: 'Scalability\n(NFR3)', value: 75, color: '#8b5cf6' },
  { label: 'Reliability\n(NFR4)', value: 88, color: '#f59e0b' },
  { label: 'Security\n(NFR5)', value: 95, color: '#ef4444' },
  { label: 'Usability\n(NFR6)', value: 85, color: '#ec4899' },
  { label: 'Maintain.\n(NFR7)', value: 80, color: '#06b6d4' },
  { label: 'Interop.\n(NFR8)', value: 92, color: '#84cc16' },
];

const cx = 50, cy = 52, r = 36, n = nfrs.length;
const toXY = (val: number, i: number) => {
  const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
  const d = (val / 100) * r;
  return { x: cx + Math.cos(angle) * d, y: cy + Math.sin(angle) * d };
};
const labelXY = (i: number) => {
  const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
  return { x: cx + Math.cos(angle) * (r + 8), y: cy + Math.sin(angle) * (r + 8) };
};
const rings = [25, 50, 75, 100];

export default function NFRRadar() {
  const points = nfrs.map((nfr, i) => toXY(nfr.value, i));
  const polygon = points.map(p => `${p.x},${p.y}`).join(' ');

  return (
    <div className="w-full h-full flex flex-col items-center justify-center">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mt-1">Non-Functional Requirements — Simulated Compliance</p>
      <div className="relative w-full" style={{ paddingBottom: '85%' }}>
        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100">
          {rings.map(ring => (
            <polygon
              key={ring}
              points={Array.from({ length: n }, (_, i) => toXY(ring, i)).map(p => `${p.x},${p.y}`).join(' ')}
              fill="none" stroke="#1e293b" strokeWidth="0.4"
            />
          ))}
          {nfrs.map((_, i) => {
            const end = toXY(100, i);
            return <line key={i} x1={cx} y1={cy} x2={end.x} y2={end.y} stroke="#1e293b" strokeWidth="0.4" />;
          })}
          <motion.polygon
            points={polygon}
            fill="rgba(34,211,238,0.15)"
            stroke="#22d3ee"
            strokeWidth="1"
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.5, duration: 0.8 }}
            style={{ transformOrigin: `${cx}px ${cy}px` }}
          />
          {nfrs.map((nfr, i) => {
            const pos = labelXY(i);
            return (
              <motion.text
                key={nfr.label}
                x={pos.x} y={pos.y}
                textAnchor="middle" dominantBaseline="middle"
                fontSize="2.8" fill={nfr.color} fontFamily="monospace"
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.8 + i * 0.1 }}
              >
                {nfr.label.split('\n').map((line, li) => (
                  <tspan key={li} x={pos.x} dy={li === 0 ? 0 : 3.5}>{line}</tspan>
                ))}
              </motion.text>
            );
          })}
          {points.map((p, i) => (
            <motion.circle
              key={i}
              cx={p.x} cy={p.y} r={1.5}
              fill={nfrs[i].color}
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 1.2 + i * 0.1, type: 'spring' }}
              style={{ transformOrigin: `${p.x}px ${p.y}px` }}
            />
          ))}
        </svg>
      </div>
    </div>
  );
}
