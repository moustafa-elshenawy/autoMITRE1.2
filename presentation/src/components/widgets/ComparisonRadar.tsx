import { motion } from 'framer-motion';

const tools = ['MS TMT', 'OWASP\nDragon', 'IriusRisk', 'VirusTotal', 'Splunk'];
const axes = ['AI/NLP', 'Multi-Framework', 'Multi-Format', 'SIEM Export', 'Mitigation Gen'];

// scores out of 10
const scores: Record<string, number[]> = {
  'MS TMT':      [0, 1, 2, 1, 2],
  'OWASP\nDragon': [0, 1, 2, 0, 2],
  'IriusRisk':   [2, 2, 3, 3, 4],
  'VirusTotal':  [3, 1, 3, 2, 1],
  'Splunk':      [4, 2, 5, 8, 2],
};
const autoMITREScores = [9, 9, 9, 9, 9];
const COLORS = ['#64748b', '#6366f1', '#8b5cf6', '#f59e0b', '#10b981'];

const toXY = (value: number, index: number, total: number, max: number, cx: number, cy: number, r: number) => {
  const angle = (Math.PI * 2 * index) / total - Math.PI / 2;
  const dist = (value / max) * r;
  return { x: cx + Math.cos(angle) * dist, y: cy + Math.sin(angle) * dist };
};

export default function ComparisonRadar() {
  const cx = 50, cy = 50, r = 38, max = 10, n = axes.length;

  const makePolygon = (scrs: number[]) =>
    scrs.map((v, i) => toXY(v, i, n, max, cx, cy, r))
       .map(p => `${p.x},${p.y}`).join(' ');

  // Grid rings
  const rings = [2, 4, 6, 8, 10];

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-2">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-1">Competitive Analysis — 5 Axes</p>
      <div className="relative w-full flex-1 min-h-0 flex items-center justify-center">
        <svg className="w-full h-full" viewBox="-20 -20 140 140" preserveAspectRatio="xMidYMid meet">
          {/* Grid rings */}
          {rings.map(ring => (
            <polygon
              key={ring}
              points={Array.from({ length: n }, (_, i) => toXY(ring, i, n, max, cx, cy, r))
                .map(p => `${p.x},${p.y}`).join(' ')}
              fill="none"
              stroke="#1e293b"
              strokeWidth="0.5"
            />
          ))}

          {/* Axis lines */}
          {axes.map((_, i) => {
            const end = toXY(max, i, n, max, cx, cy, r);
            return <line key={i} x1={cx} y1={cy} x2={end.x} y2={end.y} stroke="#1e293b" strokeWidth="0.5" />;
          })}

          {/* Tool polygons */}
          {tools.map((tool, ti) => (
            <motion.polygon
              key={tool}
              points={makePolygon(scores[tool])}
              fill={`${COLORS[ti]}15`}
              stroke={COLORS[ti]}
              strokeWidth="0.6"
              initial={{ opacity: 0 }}
              animate={{ opacity: 0.7 }}
              transition={{ delay: ti * 0.2 + 0.5 }}
            />
          ))}

          {/* AutoMITRE */}
          <motion.polygon
            points={makePolygon(autoMITREScores)}
            fill="rgba(251,191,36,0.15)"
            stroke="#fbbf24"
            strokeWidth="1.2"
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 1.5, duration: 0.6, type: 'spring' }}
            style={{ transformOrigin: `${cx}px ${cy}px` }}
          />

          {/* Axis labels */}
          {axes.map((axis, i) => {
            const pos = toXY(max + 5, i, n, max, cx, cy, r);
            return (
              <text key={axis} x={pos.x} y={pos.y} textAnchor="middle" dominantBaseline="middle"
                fontSize="3.2" fill="#94a3b8" fontFamily="monospace">{axis}</text>
            );
          })}
        </svg>
      </div>
      {/* Legend */}
      <div className="flex flex-wrap gap-2 justify-center -mt-2">
        {tools.map((t, i) => (
          <div key={t} className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[i] }} />
            <span className="text-[8px] text-slate-400 font-mono">{t.replace('\n', ' ')}</span>
          </div>
        ))}
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 rounded-full bg-amber-400" />
          <span className="text-[8px] text-amber-400 font-mono font-bold">autoMITRE</span>
        </div>
      </div>
    </div>
  );
}
