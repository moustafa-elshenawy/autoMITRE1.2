import { motion } from 'framer-motion';

export default function DesignDecisionTree() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3">
      <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-3">Design Alternative Decision</p>
      <div className="relative w-full" style={{ paddingBottom: '75%' }}>
        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 80">
          {/* Root question */}
          <motion.rect x={30} y={2} width={40} height={12} rx={3} fill="#1e293b" stroke="#475569" strokeWidth="0.8"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }} />
          <motion.text x={50} y={9} textAnchor="middle" dominantBaseline="middle" fontSize="3.5" fill="#94a3b8" fontFamily="monospace"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}>Threat Analysis Approach?</motion.text>

          {/* Branch lines */}
          {[[50,14,22,30],[50,14,50,30],[50,14,78,30]].map(([x1,y1,x2,y2],i)=>(
            <motion.line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#334155" strokeWidth="0.5"
              initial={{ pathLength: 0, opacity: 0 }} animate={{ pathLength: 1, opacity: 1 }} transition={{ delay: 0.6+i*0.1, duration: 0.4 }} />
          ))}

          {/* Three options */}
          {[
            { x: 8, y: 30, w: 28, label: 'Rule-Based\nOnly', color: '#ef4444', verdict: '✗ Rejected', vColor: '#ef4444', reason: 'Static rules\nmiss new threats' },
            { x: 36, y: 30, w: 28, label: 'ML Only', color: '#f59e0b', verdict: '✗ Rejected', vColor: '#f59e0b', reason: 'Low explainability\nlarge datasets needed' },
            { x: 64, y: 30, w: 30, label: 'Hybrid\nRule+ML+NLP', color: '#10b981', verdict: '✓ Selected', vColor: '#10b981', reason: 'Best accuracy\n+ explainability' },
          ].map((opt, i) => (
            <g key={opt.label}>
              <motion.rect x={opt.x} y={opt.y} width={opt.w} height={14} rx={3}
                fill={`${opt.color}10`} stroke={opt.color} strokeWidth="0.8"
                initial={{ opacity: 0, scale: 0.5 }} animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.8+i*0.2, type: 'spring' }}
                style={{ transformOrigin: `${opt.x+opt.w/2}px ${opt.y+7}px` }} />
              {opt.label.split('\n').map((line, li) => (
                <motion.text key={li} x={opt.x+opt.w/2} y={opt.y + 5 + li*5} textAnchor="middle" dominantBaseline="middle"
                  fontSize="3" fill={opt.color} fontFamily="monospace" fontWeight="bold"
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1+i*0.2 }}>
                  {line}
                </motion.text>
              ))}
              <motion.text x={opt.x+opt.w/2} y={opt.y+18} textAnchor="middle" fontSize="3" fill={opt.vColor} fontFamily="monospace"
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1.3+i*0.2 }}>{opt.verdict}</motion.text>
              {opt.reason.split('\n').map((line, li) => (
                <motion.text key={li} x={opt.x+opt.w/2} y={opt.y+23+li*4} textAnchor="middle" fontSize="2.5" fill="#64748b" fontFamily="monospace"
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1.5+i*0.2 }}>{line}</motion.text>
              ))}
            </g>
          ))}

          {/* Selected arrow */}
          <motion.path d="M 79 44 L 79 55 L 50 55 L 50 62" stroke="#10b981" strokeWidth="1" fill="none"
            strokeDasharray="2,1"
            initial={{ pathLength: 0, opacity: 0 }} animate={{ pathLength: 1, opacity: 1 }} transition={{ delay: 1.8, duration: 0.6 }} />

          {/* Final result box */}
          <motion.rect x={28} y={62} width={44} height={14} rx={3} fill="rgba(16,185,129,0.15)" stroke="#10b981" strokeWidth="1"
            initial={{ opacity: 0, scale: 0 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 2.2, type: 'spring' }}
            style={{ transformOrigin: '50px 69px' }} />
          <motion.text x={50} y={68} textAnchor="middle" dominantBaseline="middle" fontSize="3.5" fill="#10b981" fontFamily="monospace" fontWeight="bold"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2.4 }}>autoMITRE: Hybrid AI Engine</motion.text>
          <motion.text x={50} y={72.5} textAnchor="middle" dominantBaseline="middle" fontSize="2.8" fill="#64748b" fontFamily="monospace"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2.5 }}>SecureBERT + RAG + LLM + Rule Engine</motion.text>
        </svg>
      </div>
    </div>
  );
}
