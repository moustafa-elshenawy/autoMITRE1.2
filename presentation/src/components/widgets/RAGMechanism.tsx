import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';

const docs = [
  'T1003 — Credential Dump',
  'LSASS Memory Access',
  'Mimikatz Tool Usage',
  'D3FEND: Process Isolation',
  'NIST AC-6 Controls',
];

export default function RAGMechanism() {
  const [step, setStep] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setStep(s => (s + 1) % 5), 1800);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-3 gap-3">
      <p className="text-[11px] font-mono text-slate-400 uppercase tracking-widest">
        RAG — Retrieval-Augmented Generation
      </p>

      <div className="w-full flex gap-3 items-start">
        {/* Step 1: User Query */}
        <div className="flex-1 flex flex-col gap-2">
          <p className="text-[11px] font-mono font-bold text-cyan-400">1. User Query</p>
          <div className="bg-slate-900/60 border border-cyan-800/40 rounded-lg p-2.5">
            <p className="text-[10px] font-mono text-slate-200 leading-relaxed">
              "Mimikatz dumps credentials from LSASS"
            </p>
          </div>

          <motion.p
            animate={{ opacity: step >= 1 ? 1 : 0.2 }}
            className="text-[10px] font-mono text-slate-300 mt-1"
          >
            2. Embed → semantic vector
          </motion.p>

          {/* Vector bars */}
          <motion.div
            animate={{ opacity: step >= 1 ? 1 : 0.1 }}
            className="bg-slate-900/60 border border-purple-800/40 rounded-lg p-2 flex gap-1 items-end h-10"
          >
            {Array.from({ length: 8 }).map((_, i) => (
              <motion.div
                key={i}
                animate={{ height: step >= 1 ? `${12 + Math.sin(i * 1.3) * 8}px` : '4px' }}
                className="flex-1 rounded-sm"
                style={{ backgroundColor: '#8b5cf6' }}
                transition={{ duration: 0.4, delay: i * 0.04 }}
              />
            ))}
          </motion.div>
        </div>

        {/* Arrow */}
        <motion.div animate={{ opacity: step >= 2 ? 1 : 0.2 }} className="mt-10 text-2xl text-cyan-400">→</motion.div>

        {/* Step 3: ChromaDB */}
        <div className="flex-1 flex flex-col gap-2">
          <p className="text-[11px] font-mono font-bold text-purple-400">3. ChromaDB Search</p>
          <div className="flex flex-col gap-1">
            {docs.map((doc, i) => (
              <motion.div
                key={doc}
                animate={{
                  opacity: step >= 2 ? 1 : 0.1,
                  backgroundColor: step >= 3 && i < 3 ? 'rgba(16,185,129,0.12)' : 'rgba(15,23,42,0.5)',
                  borderColor: step >= 3 && i < 3 ? 'rgba(16,185,129,0.5)' : 'rgba(51,65,85,0.5)',
                }}
                transition={{ delay: i * 0.1 }}
                className="text-[9.5px] font-mono px-2 py-1 rounded border"
                style={{ color: step >= 3 && i < 3 ? '#10b981' : '#64748b' }}
              >
                {step >= 3 && i < 3 ? '✓ ' : '  '}{doc}
              </motion.div>
            ))}
          </div>
        </div>

        {/* Arrow */}
        <motion.div animate={{ opacity: step >= 3 ? 1 : 0.2 }} className="mt-10 text-2xl text-emerald-400">→</motion.div>

        {/* Step 4: Grounded Output */}
        <div className="flex-1 flex flex-col gap-2">
          <p className="text-[11px] font-mono font-bold text-emerald-400">4. Grounded Output</p>
          <motion.div
            animate={{ opacity: step >= 4 ? 1 : 0.1, borderColor: step >= 4 ? 'rgba(16,185,129,0.6)' : 'rgba(51,65,85,0.3)' }}
            className="bg-emerald-950/30 border rounded-lg p-2.5"
          >
            <p className="text-[9.5px] font-mono text-emerald-300 leading-relaxed">
              Technique: T1003.001<br />
              Tactic: Credential Access<br />
              D3FEND: Process Isolation<br />
              NIST: AC-6 (Least Privilege)
            </p>
          </motion.div>
          <motion.p
            animate={{ opacity: step >= 4 ? 1 : 0 }}
            className="text-[10px] text-emerald-400 font-mono font-bold"
          >
            ✓ Zero hallucination
          </motion.p>
        </div>
      </div>
    </div>
  );
}
