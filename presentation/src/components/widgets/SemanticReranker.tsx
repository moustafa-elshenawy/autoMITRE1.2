import React from 'react';
import { motion } from 'framer-motion';
import { Filter, Brain, Target, ShieldCheck, XCircle } from 'lucide-react';

export default function SemanticReranker() {
  const predictions = [
    { name: 'T1059.001 (PowerShell)', bertConf: '0.92', sim: '0.88', pass: true },
    { name: 'T1078 (Valid Accounts)', bertConf: '0.85', sim: '0.21', pass: false },
    { name: 'T1543.003 (Windows Service)', bertConf: '0.78', sim: '0.65', pass: true },
  ];

  return (
    <div className="w-full h-full flex flex-col items-center justify-center space-y-6">
      <div className="text-center mb-4">
        <h3 className="text-emerald-400 font-mono tracking-widest text-sm uppercase">Hallucination Filter Pipeline</h3>
      </div>
      
      <div className="flex w-full max-w-4xl justify-between items-stretch gap-6">
        {/* Step 1: SecureBERT */}
        <div className="flex-1 border border-cyan-500/30 bg-cyan-900/10 rounded-xl p-4 flex flex-col">
          <div className="flex items-center gap-2 mb-4 text-cyan-300">
            <Brain className="w-5 h-5" />
            <h4 className="font-semibold text-sm">1. SecureBERT Output</h4>
          </div>
          <div className="flex-1 flex flex-col gap-3 justify-center">
            {predictions.map((p, i) => (
              <motion.div 
                key={i}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.2 }}
                className="bg-slate-800/80 p-3 rounded border border-slate-700 text-xs text-slate-300 flex justify-between"
              >
                <span>{p.name}</span>
                <span className="text-cyan-400">Conf: {p.bertConf}</span>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Step 2: The Filter */}
        <div className="flex flex-col justify-center items-center">
          <motion.div 
            animate={{ 
              boxShadow: ['0 0 0px #10b981', '0 0 20px #10b981', '0 0 0px #10b981']
            }}
            transition={{ duration: 2, repeat: Infinity }}
            className="w-16 h-16 rounded-full bg-emerald-500/20 border-2 border-emerald-500 flex items-center justify-center z-10"
          >
            <Filter className="w-6 h-6 text-emerald-400" />
          </motion.div>
          <div className="text-[10px] text-emerald-400 mt-2 font-mono text-center">
            all-mpnet-base-v2<br/>
            Threshold &gt; 0.45
          </div>
        </div>

        {/* Step 3: Verified Results */}
        <div className="flex-1 border border-emerald-500/30 bg-emerald-900/10 rounded-xl p-4 flex flex-col">
          <div className="flex items-center gap-2 mb-4 text-emerald-400">
            <Target className="w-5 h-5" />
            <h4 className="font-semibold text-sm">2. Semantic Verification</h4>
          </div>
          <div className="flex-1 flex flex-col gap-3 justify-center">
            {predictions.map((p, i) => (
              <motion.div 
                key={`res-${i}`}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 1 + i * 0.2 }}
                className={`p-3 rounded border text-xs flex justify-between items-center ${
                  p.pass 
                    ? 'bg-emerald-900/20 border-emerald-500/50 text-emerald-300' 
                    : 'bg-red-900/20 border-red-500/50 text-red-300 opacity-50'
                }`}
              >
                <div className="flex items-center gap-2">
                  {p.pass ? <ShieldCheck className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                  <span>{p.name}</span>
                </div>
                <span>Sim: {p.sim}</span>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
