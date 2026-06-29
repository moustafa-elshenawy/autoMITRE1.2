import React from 'react';
import { motion } from 'framer-motion';
import { Server, Zap, Database, Activity, ArrowRightLeft, ShieldCheck } from 'lucide-react';

export default function SiemSoarIntegration() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center space-y-8">
      <div className="text-center mb-4">
        <h3 className="text-cyan-400 font-mono tracking-widest text-sm uppercase">Active Defense Orchestration</h3>
        <p className="text-slate-400 text-xs mt-2 max-w-lg">
          Transforming autoMITRE from an analytical intelligence platform into a fully automated response trigger for enterprise security operations.
        </p>
      </div>

      <div className="flex w-full max-w-4xl justify-between items-center relative h-64">
        
        {/* autoMITRE Core */}
        <motion.div 
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex flex-col items-center z-10 w-48"
        >
          <div className="w-20 h-20 bg-cyan-900/30 border-2 border-cyan-500 rounded-2xl flex items-center justify-center shadow-[0_0_20px_rgba(6,182,212,0.3)] mb-4 relative">
            <Server className="w-8 h-8 text-cyan-400" />
            <motion.div 
              animate={{ rotate: 360 }}
              transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
              className="absolute inset-0 border border-cyan-400/30 rounded-2xl border-dashed"
            />
          </div>
          <span className="text-cyan-400 font-bold text-sm text-center">autoMITRE<br/>Engine</span>
        </motion.div>

        {/* Animated Connection 1 (SIEM) */}
        <div className="absolute left-[15%] right-[50%] top-[30%] h-0.5 border-t-2 border-dashed border-slate-600 z-0">
          <motion.div 
            animate={{ x: ["0%", "100%"] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
            className="absolute top-1/2 -translate-y-1/2 -ml-2"
          >
            <ArrowRightLeft className="w-4 h-4 text-emerald-400" />
          </motion.div>
        </div>

        {/* Animated Connection 2 (SOAR) */}
        <div className="absolute left-[15%] right-[15%] top-[70%] h-0.5 border-t-2 border-dashed border-slate-600 z-0">
          <motion.div 
            animate={{ x: ["0%", "100%"] }}
            transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
            className="absolute top-1/2 -translate-y-1/2 -ml-2"
          >
            <Zap className="w-4 h-4 text-purple-400" />
          </motion.div>
        </div>

        {/* Target Systems Stack */}
        <div className="flex flex-col justify-between h-full z-10 w-56 ml-auto">
          
          {/* SIEM Block */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-emerald-900/20 border border-emerald-500/40 rounded-xl p-4 flex flex-col relative overflow-hidden"
          >
            <div className="flex items-center gap-3 mb-2 text-emerald-400">
              <Database className="w-5 h-5" />
              <span className="font-bold text-sm">SIEM Integration</span>
            </div>
            <div className="text-xs text-slate-300">
              Bi-directional sync with <span className="text-emerald-300">Splunk, QRadar, Wazuh</span>. Feed STIX 2.1 alerts directly into analyst queues.
            </div>
          </motion.div>

          {/* SOAR Block */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.6 }}
            className="bg-purple-900/20 border border-purple-500/40 rounded-xl p-4 flex flex-col mt-auto relative overflow-hidden"
          >
            <div className="flex items-center gap-3 mb-2 text-purple-400">
              <Activity className="w-5 h-5" />
              <span className="font-bold text-sm">SOAR Playbooks</span>
            </div>
            <div className="text-xs text-slate-300">
              Trigger automated <span className="text-purple-300">Cortex XSOAR / Splunk SOAR</span> responses based on autoMITRE's ML severity prediction.
            </div>
          </motion.div>

        </div>
      </div>
      
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1 }}
        className="flex items-center gap-2 mt-8 bg-slate-800/80 px-6 py-3 rounded-full border border-slate-700 text-xs text-slate-300"
      >
        <ShieldCheck className="w-4 h-4 text-emerald-400" />
        Reduces MTTD & MTTR by executing generated mitigations instantaneously without human bottleneck.
      </motion.div>
    </div>
  );
}
