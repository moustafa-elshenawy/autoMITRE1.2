import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';

const nodes = [
  { id: 'T1003.001', label: 'LSASS Memory' },
  { id: 'T1003.002', label: 'SAM Database' },
  { id: 'T1003.004', label: 'LSA Secrets' }
];

export default function AccuracyContext() {
  const [sims, setSims] = useState<number[]>([0, 0, 0]);

  useEffect(() => {
    // Generate static but realistic looking similarity scores on mount
    setSims([82, 79, 81]);
  }, []);

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-6">
      <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">The Ambiguity Problem</p>
      
      <div className="flex flex-col items-center w-full max-w-lg bg-slate-900/50 p-5 rounded-xl border border-slate-800 shadow-xl mt-2">
        <p className="text-xs text-slate-400 font-mono mb-3 uppercase tracking-widest">Input Log (Missing Context)</p>
        <p className="text-sm font-bold text-amber-400 font-mono text-center">"Suspicious process accessed credential storage"</p>
      </div>
      
      <motion.div 
        animate={{ y: [0, 5, 0] }} 
        transition={{ duration: 2, repeat: Infinity }}
        className="text-slate-500 font-mono text-sm"
      >
        ↓ Semantic Search ↓
      </motion.div>
      
      <div className="flex gap-6 w-full justify-center max-w-4xl">
        {nodes.map((node, i) => (
          <motion.div 
            key={node.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 + i * 0.2 }}
            className="flex flex-col items-center gap-2 p-4 border border-slate-700/50 rounded-xl bg-slate-900/40 w-40"
          >
            <span className="text-sm font-bold text-cyan-400 font-mono">{node.id}</span>
            <span className="text-xs text-slate-300 font-mono text-center">{node.label}</span>
            <motion.div 
              initial={{ opacity: 0 }} 
              animate={{ opacity: 1 }} 
              transition={{ delay: 1.5 + i * 0.2 }}
              className="text-[11px] text-slate-400 font-mono mt-2 bg-slate-800/50 px-2 py-1 rounded w-full text-center"
            >
              Similarity: <span className="text-amber-400">{sims[i]}%</span>
            </motion.div>
          </motion.div>
        ))}
      </div>
      
      <motion.p 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2.5 }}
        className="text-sm text-slate-400 font-mono text-center mt-4 max-w-xl leading-relaxed"
      >
        The AI correctly identifies the T1003 Tactic, but struggles to pick the exact sub-technique without surrounding timeline context.
      </motion.p>
    </div>
  );
}
