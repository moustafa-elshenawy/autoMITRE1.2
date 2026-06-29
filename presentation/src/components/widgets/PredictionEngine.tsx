import React from 'react';
import { motion } from 'framer-motion';
import { FastForward, ShieldQuestion, Target, GitPullRequest } from 'lucide-react';

export default function PredictionEngine() {
  const killChain = [
    { name: 'Initial Access', status: 'past' },
    { name: 'Execution', status: 'past' },
    { name: 'Privilege Escalation', status: 'current' },
    { name: 'Credential Access', status: 'predicted' },
    { name: 'Lateral Movement', status: 'predicted' },
  ];

  return (
    <div className="w-full h-full flex flex-col items-center justify-center space-y-8">
      <div className="text-center">
        <h3 className="text-purple-400 font-mono tracking-widest text-sm uppercase mb-2">Predictive Attack Path Generation</h3>
        <p className="text-slate-400 text-xs max-w-lg">
          The LLM analyzes the current kill-chain position and generates probabilistic next-step actions the adversary is likely to take.
        </p>
      </div>

      <div className="w-full max-w-4xl flex items-center justify-between mt-8 relative">
        {/* Connection Line */}
        <div className="absolute top-1/2 left-0 right-0 h-1 bg-slate-800 -translate-y-1/2 z-0"></div>

        {killChain.map((step, index) => (
          <div key={index} className="relative z-10 flex flex-col items-center gap-3">
            <motion.div
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: index * 0.2 }}
              className={`w-12 h-12 rounded-full border-2 flex items-center justify-center ${
                step.status === 'past' 
                  ? 'bg-slate-800 border-slate-600 text-slate-400'
                  : step.status === 'current'
                  ? 'bg-red-900/40 border-red-500 text-red-400'
                  : 'bg-purple-900/40 border-purple-500 border-dashed text-purple-400'
              }`}
            >
              {step.status === 'past' ? <Target className="w-5 h-5" /> : 
               step.status === 'current' ? <ShieldQuestion className="w-5 h-5" /> : 
               <FastForward className="w-5 h-5" />}
            </motion.div>
            
            <motion.div
              initial={{ y: 10, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.2 + index * 0.2 }}
              className="text-center"
            >
              <div className={`text-[10px] font-mono uppercase tracking-wider mb-1 ${
                step.status === 'predicted' ? 'text-purple-400 font-bold' : 'text-slate-500'
              }`}>
                {step.status === 'current' ? 'DETECTED' : step.status === 'predicted' ? 'PREDICTED' : 'HISTORICAL'}
              </div>
              <div className="text-xs font-semibold text-slate-300 w-24 leading-tight">{step.name}</div>
            </motion.div>
          </div>
        ))}
      </div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.5 }}
        className="mt-8 bg-purple-900/20 border border-purple-500/30 rounded-xl p-4 w-full max-w-2xl flex items-start gap-4"
      >
        <div className="p-2 bg-purple-500/20 rounded-lg text-purple-400">
          <GitPullRequest className="w-6 h-6" />
        </div>
        <div>
          <h4 className="text-sm font-bold text-purple-300 mb-1">LLM Generated Prediction</h4>
          <p className="text-xs text-slate-300 leading-relaxed">
            "Based on the execution of <span className="text-red-400 font-mono">whoami /priv</span> and <span className="text-red-400 font-mono">mimikatz</span>, the adversary has achieved privilege escalation and is currently positioned to dump LSASS memory. The most probable next step is Lateral Movement via Pass-the-Hash (T1550.002) to target the Domain Controller."
          </p>
        </div>
      </motion.div>
    </div>
  );
}
