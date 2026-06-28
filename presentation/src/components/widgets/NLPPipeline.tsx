import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';

const rawText = 'adversary uses Mimikatz to dump LSASS credential material';
const tokens = rawText.split(' ');

const stages = [
  { label: 'Raw Text Input', color: '#64748b' },
  { label: 'Tokenization', color: '#0ea5e9' },
  { label: 'spaCy / NLTK NER', color: '#8b5cf6' },
  { label: 'SecureBERT Embed', color: '#10b981' },
  { label: 'Threat Vector', color: '#f59e0b' },
  { label: 'ATT&CK T1003', color: '#ef4444' },
];

export default function NLPPipeline() {
  const [stage, setStage] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setStage(s => (s + 1) % stages.length), 1500);
    return () => clearInterval(id);
  }, []);

  const tokenColors: Record<string, string> = {
    'Mimikatz': '#ef4444',
    'LSASS': '#f59e0b',
    'dump': '#8b5cf6',
    'credential': '#10b981',
    'material': '#06b6d4',
  };

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-3">
      <p className="text-[12px] font-mono text-slate-400 uppercase tracking-widest mb-2">NLP Processing Pipeline — Live Simulation</p>

      {/* Stage indicator */}
      <div className="flex gap-1 w-full justify-center">
        {stages.map((s, i) => (
          <motion.div
            key={s.label}
            animate={{ opacity: i <= stage ? 1 : 0.2, scale: i === stage ? 1.1 : 1 }}
            className="flex-1 py-2 rounded-md text-center text-[10px] font-mono"
            style={{ backgroundColor: i <= stage ? `${s.color}20` : '#1e293b', color: i <= stage ? s.color : '#475569', border: `1px solid ${i === stage ? s.color : '#1e293b'}` }}
          >
            {s.label}
          </motion.div>
        ))}
      </div>

      {/* Token display */}
      <div className="flex flex-wrap gap-1.5 justify-center p-3 rounded-xl border border-slate-800/50 bg-slate-950/50 w-full">
        {tokens.map((token, i) => (
          <motion.span
            key={i}
            animate={{
              backgroundColor: stage >= 1 && tokenColors[token] ? `${tokenColors[token]}20` : 'transparent',
              color: stage >= 1 && tokenColors[token] ? tokenColors[token] : '#94a3b8',
              borderColor: stage >= 1 && tokenColors[token] ? tokenColors[token] : '#334155',
              scale: stage >= 2 && tokenColors[token] ? 1.1 : 1,
            }}
            transition={{ duration: 0.4 }}
            className="text-base font-mono px-3 py-1 rounded border"
          >
            {token}
          </motion.span>
        ))}
      </div>

      {/* Result */}
      <motion.div
        animate={{ opacity: stage >= 4 ? 1 : 0.3 }}
        className="w-full flex gap-2 justify-center"
      >
        {[
          { label: 'Entity: Mimikatz', color: '#ef4444' },
          { label: 'Action: Credential Dump', color: '#8b5cf6' },
          { label: 'Target: LSASS Process', color: '#f59e0b' },
          { label: 'Maps to: T1003', color: '#10b981' },
        ].map((tag) => (
          <span key={tag.label} className="text-[11px] font-mono px-3 py-1.5 rounded-lg"
            style={{ color: tag.color, backgroundColor: `${tag.color}15`, border: `1px solid ${tag.color}40` }}>
            {tag.label}
          </span>
        ))}
      </motion.div>
    </div>
  );
}
