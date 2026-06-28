import { motion } from 'framer-motion';

const center = { x: 50, y: 50 };
const stakeholders = [
  { label: 'SOC Analyst', color: '#0ea5e9', angle: 270, dist: 35 },
  { label: 'Sys Admin', color: '#8b5cf6', angle: 342, dist: 35 },
  { label: 'Security Eng', color: '#10b981', angle: 54, dist: 35 },
  { label: 'IR Team', color: '#f59e0b', angle: 126, dist: 35 },
  { label: 'Compliance', color: '#ec4899', angle: 198, dist: 35 },
];

const toXY = (angle: number, dist: number) => ({
  x: center.x + Math.cos((angle * Math.PI) / 180) * dist,
  y: center.y + Math.sin((angle * Math.PI) / 180) * dist,
});

export default function StakeholderOrbit() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-1">Who Benefits from autoMITRE</p>
      <div className="relative w-full flex-1 min-h-0 flex items-center justify-center mt-2">
        <svg className="w-full h-full" viewBox="-15 -15 130 130" preserveAspectRatio="xMidYMid meet">
          {/* Orbit circle */}
          <motion.circle
            cx={50} cy={50} r={35}
            fill="none" stroke="#1e293b" strokeWidth="0.5" strokeDasharray="2,2"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          />

          {/* Lines from center to stakeholders */}
          {stakeholders.map((s, i) => {
            const pos = toXY(s.angle, s.dist);
            return (
              <motion.line
                key={s.label}
                x1={50} y1={50} x2={pos.x} y2={pos.y}
                stroke={`${s.color}30`}
                strokeWidth="0.4"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                transition={{ delay: 1 + i * 0.2, duration: 0.4 }}
              />
            );
          })}

          {/* Center: autoMITRE */}
          <motion.circle
            cx={50} cy={50} r={9}
            fill="rgba(34,211,238,0.15)"
            stroke="#22d3ee"
            strokeWidth="1"
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.3, type: 'spring' }}
            style={{ transformOrigin: '50px 50px' }}
          />
          <motion.text
            x={50} y={49} textAnchor="middle" dominantBaseline="middle"
            fontSize="3.5" fill="#22d3ee" fontWeight="bold" fontFamily="monospace"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6 }}
          >auto</motion.text>
          <motion.text
            x={50} y={53} textAnchor="middle" dominantBaseline="middle"
            fontSize="3.5" fill="#22d3ee" fontWeight="bold" fontFamily="monospace"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.7 }}
          >MITRE</motion.text>

          {/* Stakeholder nodes */}
          {stakeholders.map((s, i) => {
            const pos = toXY(s.angle, s.dist);
            const anchor = s.angle === 270 || s.angle === 90 ? "middle" : (s.angle < 90 || s.angle > 270 ? "start" : "end");
            const labelPos = toXY(s.angle, s.dist + 8);
            return (
              <g key={s.label}>
                <motion.circle
                  cx={pos.x} cy={pos.y} r={5}
                  fill={`${s.color}20`}
                  stroke={s.color}
                  strokeWidth="0.7"
                  initial={{ scale: 0, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: 1.2 + i * 0.2, type: 'spring' }}
                  style={{ transformOrigin: `${pos.x}px ${pos.y}px` }}
                />
                <motion.text
                  x={labelPos.x} y={s.angle === 270 ? labelPos.y - 2 : labelPos.y}
                  textAnchor={anchor} dominantBaseline="middle"
                  fontSize="3" fill={s.color} fontFamily="monospace"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 1.5 + i * 0.2 }}
                >
                  {s.label}
                </motion.text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
