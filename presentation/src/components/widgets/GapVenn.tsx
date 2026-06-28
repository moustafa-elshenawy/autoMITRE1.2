import { motion } from 'framer-motion';

export default function GapVenn() {
  const circles = [
    { label: 'AI / NLP\nEngines', color: '#0ea5e9', cx: 38, cy: 42 },
    { label: 'Multi-Framework\nMapping', color: '#8b5cf6', cx: 62, cy: 42 },
    { label: 'Multi-Format\nIngestion', color: '#10b981', cx: 50, cy: 62 },
  ];

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-2">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-2">The Research Gap — No Tool Covers All Three</p>
      <div className="relative w-full" style={{ paddingBottom: '75%' }}>
        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100">
          {/* Circles */}
          {circles.map((c, i) => (
            <motion.circle
              key={c.label}
              cx={c.cx} cy={c.cy} r={22}
              fill={`${c.color}15`}
              stroke={c.color}
              strokeWidth="0.8"
              initial={{ opacity: 0, r: 0 }}
              animate={{ opacity: 1, r: 22 }}
              transition={{ delay: i * 0.4, duration: 0.6 }}
            />
          ))}

          {/* Center intersection — autoMITRE */}
          <motion.circle
            cx={50} cy={49} r={7}
            fill="rgba(251,191,36,0.3)"
            stroke="#fbbf24"
            strokeWidth="1"
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 1.5, duration: 0.5, type: 'spring' }}
            style={{ transformOrigin: '50px 49px' }}
          />
          <motion.text
            x={50} y={49} textAnchor="middle" dominantBaseline="middle"
            fontSize="3.5" fontWeight="bold" fill="#fbbf24" fontFamily="monospace"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.8 }}
          >
            AUTO
          </motion.text>
          <motion.text
            x={50} y={52.5} textAnchor="middle" dominantBaseline="middle"
            fontSize="3.5" fontWeight="bold" fill="#fbbf24" fontFamily="monospace"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.9 }}
          >
            MITRE
          </motion.text>

          {/* Labels */}
          {circles.map((c, i) => {
            const lx = c.cx + (c.cx < 50 ? -12 : c.cx > 50 ? 12 : 0);
            const ly = c.cy + (c.cy > 55 ? 12 : -12);
            return (
              <motion.text
                key={c.label + 'label'}
                x={lx} y={ly}
                textAnchor="middle"
                fontSize="3.5"
                fill={c.color}
                fontFamily="monospace"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.4 + 0.5 }}
              >
                {c.label.split('\n').map((line, li) => (
                  <tspan key={li} x={lx} dy={li === 0 ? 0 : 4.5}>{line}</tspan>
                ))}
              </motion.text>
            );
          })}
        </svg>
      </div>
      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2.2 }}
        className="text-[10px] text-amber-400 font-mono text-center mt-1"
      >
        ⭐ autoMITRE is the only system at the intersection of all three
      </motion.p>
    </div>
  );
}
