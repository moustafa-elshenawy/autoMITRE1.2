import { motion } from 'framer-motion';

// All coordinates are in a 320×220 viewBox for full control
const W = 320, H = 220;

// Root box
const ROOT = { x: 80, y: 8, w: 160, h: 28 };

// Three option boxes — evenly spaced
const OPTS = [
  { x: 8,   y: 70, w: 88, label: ['Rule-Based', 'Only'],    color: '#ef4444', verdict: '✗ Rejected', reason: ['Static rules', 'miss new threats'] },
  { x: 116, y: 70, w: 88, label: ['ML Only'],               color: '#f59e0b', verdict: '✗ Rejected', reason: ['Low explainability', 'large datasets'] },
  { x: 224, y: 70, w: 88, label: ['Hybrid', 'Rule+ML+NLP'], color: '#10b981', verdict: '✓ Selected', reason: ['Best accuracy', '+ explainability'] },
];

// Final result box
const RESULT = { x: 80, y: 168, w: 160, h: 36 };

// Branch origins (bottom of root)
const ROOT_MID_X = ROOT.x + ROOT.w / 2;
const ROOT_BOT_Y = ROOT.y + ROOT.h;

export default function DesignDecisionTree() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-2">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-2">Design Alternative Decision</p>
      <div className="w-full flex-1 min-h-0 flex items-center justify-center">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full" preserveAspectRatio="xMidYMid meet">

          {/* Root question box */}
          <motion.rect x={ROOT.x} y={ROOT.y} width={ROOT.w} height={ROOT.h} rx={5}
            fill="#1e293b" stroke="#475569" strokeWidth="1"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }} />
          <motion.text x={ROOT.x + ROOT.w / 2} y={ROOT.y + ROOT.h / 2}
            textAnchor="middle" dominantBaseline="middle" fontSize="8.5"
            fill="#94a3b8" fontFamily="monospace"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}>
            Threat Analysis Approach?
          </motion.text>

          {/* Branch lines from root to each option */}
          {OPTS.map((opt, i) => {
            const cx = opt.x + opt.w / 2;
            return (
              <motion.path key={i}
                d={`M ${ROOT_MID_X} ${ROOT_BOT_Y} L ${ROOT_MID_X} ${ROOT_BOT_Y + 8} L ${cx} ${ROOT_BOT_Y + 8} L ${cx} ${opt.y}`}
                fill="none" stroke="#334155" strokeWidth="1"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                transition={{ delay: 0.6 + i * 0.1, duration: 0.5 }} />
            );
          })}

          {/* Option boxes */}
          {OPTS.map((opt, i) => {
            const cx = opt.x + opt.w / 2;
            const boxH = 30;
            return (
              <g key={opt.label.join('')}>
                <motion.rect x={opt.x} y={opt.y} width={opt.w} height={boxH} rx={4}
                  fill={`${opt.color}18`} stroke={opt.color} strokeWidth="1"
                  initial={{ opacity: 0, scale: 0.6 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.9 + i * 0.2, type: 'spring' }}
                  style={{ transformOrigin: `${cx}px ${opt.y + boxH / 2}px` }} />
                {opt.label.map((line, li) => (
                  <motion.text key={li}
                    x={cx} y={opt.y + 10 + li * 10}
                    textAnchor="middle" dominantBaseline="middle"
                    fontSize="7.5" fill={opt.color} fontFamily="monospace" fontWeight="bold"
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1.1 + i * 0.2 }}>
                    {line}
                  </motion.text>
                ))}
                {/* Verdict */}
                <motion.text x={cx} y={opt.y + boxH + 9}
                  textAnchor="middle" fontSize="7.5" fill={opt.color} fontFamily="monospace"
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1.4 + i * 0.15 }}>
                  {opt.verdict}
                </motion.text>
                {/* Reason lines */}
                {opt.reason.map((r, ri) => (
                  <motion.text key={ri}
                    x={cx} y={opt.y + boxH + 19 + ri * 9}
                    textAnchor="middle" fontSize="6.5" fill="#64748b" fontFamily="monospace"
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1.6 + i * 0.15 }}>
                    {r}
                  </motion.text>
                ))}
              </g>
            );
          })}

          {/* Arrow from Hybrid down to result */}
          {(() => {
            const cx = OPTS[2].x + OPTS[2].w / 2;
            const optBot = OPTS[2].y + 30;
            return (
              <motion.path
                d={`M ${cx} ${optBot} L ${cx} ${RESULT.y - 8} L ${RESULT.x + RESULT.w / 2} ${RESULT.y - 8} L ${RESULT.x + RESULT.w / 2} ${RESULT.y}`}
                fill="none" stroke="#10b981" strokeWidth="1.2" strokeDasharray="4,2"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                transition={{ delay: 2.0, duration: 0.7 }} />
            );
          })()}

          {/* Final result box */}
          <motion.rect x={RESULT.x} y={RESULT.y} width={RESULT.w} height={RESULT.h} rx={5}
            fill="rgba(16,185,129,0.15)" stroke="#10b981" strokeWidth="1.2"
            initial={{ opacity: 0, scale: 0 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 2.4, type: 'spring' }}
            style={{ transformOrigin: `${RESULT.x + RESULT.w / 2}px ${RESULT.y + RESULT.h / 2}px` }} />
          <motion.text x={RESULT.x + RESULT.w / 2} y={RESULT.y + 14}
            textAnchor="middle" dominantBaseline="middle"
            fontSize="8.5" fill="#10b981" fontFamily="monospace" fontWeight="bold"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2.6 }}>
            autoMITRE: Hybrid AI Engine
          </motion.text>
          <motion.text x={RESULT.x + RESULT.w / 2} y={RESULT.y + 26}
            textAnchor="middle" dominantBaseline="middle"
            fontSize="7" fill="#64748b" fontFamily="monospace"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2.7 }}>
            SecureBERT + RAG + LLM + Rule Engine
          </motion.text>

        </svg>
      </div>
    </div>
  );
}
