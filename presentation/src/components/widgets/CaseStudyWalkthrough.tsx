import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';

const steps = [
  {
    step: '01',
    title: 'Raw Input',
    detail: '"adversary uses Mimikatz to dump credential material from LSASS"',
    color: '#64748b',
    type: 'input',
  },
  {
    step: '02',
    title: 'SecureBERT Extraction',
    detail: 'Entity: Mimikatz | Action: credential dump | Target: LSASS process',
    color: '#8b5cf6',
    type: 'ai',
  },
  {
    step: '03',
    title: 'ATT&CK Framework Mapping',
    detail: 'T1003 — OS Credential Dumping | Tactic: Credential Access',
    color: '#ef4444',
    type: 'map',
  },
  {
    step: '04',
    title: 'Defensive Framework Mapping',
    detail: 'D3FEND: Credential Access Prevention | NIST AC-6: Least Privilege',
    color: '#0ea5e9',
    type: 'defend',
  },
  {
    step: '05',
    title: 'Mitigation Output',
    detail: '1. Enable Credential Guard  2. Block Mimikatz signatures  3. Implement PAW',
    color: '#10b981',
    type: 'output',
  },
];

export default function CaseStudyWalkthrough() {
  const [active, setActive] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setActive(a => (a + 1) % steps.length), 2000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 gap-4">
      <p className="text-xs font-mono text-slate-400 uppercase tracking-widest">Live Case Study: Mimikatz Credential Dumping</p>

      <div className="w-full flex flex-col gap-2.5 max-w-4xl">
        {steps.map((step, i) => (
          <motion.div
            key={step.step}
            animate={{
              opacity: i <= active ? 1 : 0.2,
              borderColor: i === active ? step.color : `${step.color}30`,
              backgroundColor: i === active ? `${step.color}12` : `${step.color}04`,
              scale: i === active ? 1.02 : 1,
            }}
            transition={{ duration: 0.3 }}
            className="flex items-start gap-4 p-3.5 rounded-xl border"
          >
            <div
              className="w-10 h-10 rounded-full flex items-center justify-center shrink-0 text-sm font-bold font-mono"
              style={{ color: step.color, backgroundColor: `${step.color}20`, border: `1.5px solid ${step.color}40` }}
            >
              {step.step}
            </div>
            <div className="flex-1 min-w-0 flex flex-col justify-center py-0.5">
              <p className="text-sm font-bold font-mono" style={{ color: step.color }}>{step.title}</p>
              <p className="text-xs text-slate-300 font-mono leading-relaxed mt-1 truncate">{step.detail}</p>
            </div>
            <motion.div animate={{ opacity: i <= active ? 1 : 0 }} className="self-center pr-2">
              <span className="text-xl font-bold" style={{ color: step.color }}>✓</span>
            </motion.div>
          </motion.div>
        ))}
      </div>

      <p className="text-xs text-slate-500 font-mono mt-2">Total end-to-end time: ~1.2 seconds (Groq cloud mode)</p>
    </div>
  );
}
