import React from 'react';
import { motion } from 'framer-motion';
import { Activity, ShieldAlert, Cpu } from 'lucide-react';

export default function ThreatSeverity() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center space-y-8">
      <div className="text-center">
        <h3 className="text-amber-400 font-mono tracking-widest text-sm uppercase mb-2">XGBoost Risk Convergence</h3>
        <p className="text-slate-400 text-xs max-w-lg">
          Both the NLP pipeline and the Deep-Learning pipeline feed into the final severity predictor to calculate a CVSS v3.1 aligned score.
        </p>
      </div>
      
      <div className="flex w-full max-w-3xl items-center justify-between relative">
        {/* Inputs */}
        <div className="flex flex-col gap-6 flex-1">
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="p-4 rounded-xl border border-cyan-500/30 bg-cyan-900/10 text-center"
          >
            <div className="text-cyan-400 text-sm font-bold mb-1">RAG Pipeline</div>
            <div className="text-xs text-slate-300">Base CVSS of Mapped Techniques</div>
          </motion.div>
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="p-4 rounded-xl border border-purple-500/30 bg-purple-900/10 text-center"
          >
            <div className="text-purple-400 text-sm font-bold mb-1">SecureBERT</div>
            <div className="text-xs text-slate-300">Multi-label Severity Flags</div>
          </motion.div>
        </div>

        {/* Model */}
        <div className="flex flex-col items-center justify-center flex-1 px-8 relative z-10">
          <motion.div 
            animate={{ rotate: 360 }}
            transition={{ duration: 20, ease: "linear", repeat: Infinity }}
            className="absolute inset-0 flex items-center justify-center opacity-20 pointer-events-none"
          >
            <Cpu className="w-32 h-32 text-amber-500" />
          </motion.div>
          <motion.div 
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.4 }}
            className="w-24 h-24 rounded-2xl bg-amber-900/30 border-2 border-amber-500 flex items-center justify-center shadow-[0_0_30px_rgba(245,158,11,0.2)]"
          >
            <Activity className="w-10 h-10 text-amber-400" />
          </motion.div>
          <div className="text-amber-400 font-mono text-xs mt-3 bg-slate-900 px-2 py-1 rounded">XGBoost Regressor</div>
        </div>

        {/* Output */}
        <div className="flex-1">
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.8 }}
            className="p-6 rounded-xl border-2 border-red-500/50 bg-red-900/20 text-center relative overflow-hidden"
          >
            <div className="absolute top-0 right-0 p-2">
              <ShieldAlert className="w-5 h-5 text-red-400 opacity-50" />
            </div>
            <div className="text-slate-400 text-xs font-mono uppercase tracking-widest mb-2">Final Risk Score</div>
            <div className="text-4xl font-bold text-red-400">8.4</div>
            <div className="text-red-400/80 text-xs font-bold mt-1 uppercase">High Severity</div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
