import React from 'react';
import { motion } from 'framer-motion';
import { Server, Zap, Database, Activity, ArrowRightLeft, ShieldCheck } from 'lucide-react';

export default function SiemSoarIntegration() {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center space-y-6">
      <div className="text-center mb-6">
        <h3 className="text-cyan-400 font-mono tracking-widest text-sm uppercase">Active Defense Orchestration</h3>
        <p className="text-slate-400 text-xs mt-2 max-w-lg">
          Transforming autoMITRE from an analytical intelligence platform into a fully automated response trigger for enterprise security operations.
        </p>
      </div>

      <div className="flex w-full max-w-4xl justify-between items-center relative h-64 mt-4">
        
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
          <span className="text-cyan-400 font-bold text-sm text-center leading-tight">autoMITRE<br/>Engine</span>
        </motion.div>

        {/* Forking Connection Lines */}
        <div className="flex-1 h-36 relative mx-4">
          {/* Center horizontal line from autoMITRE to fork */}
          <div className="absolute left-0 top-1/2 w-8 border-t-2 border-dashed border-slate-500 -translate-y-1/2" />
          
          {/* Vertical fork line */}
          <div className="absolute left-8 top-0 bottom-0 border-l-2 border-dashed border-slate-500" />

          {/* Top horizontal line to SIEM */}
          <div className="absolute left-8 top-0 right-0 border-t-2 border-dashed border-slate-500">
            <div className="absolute inset-0 w-full overflow-hidden">
              <motion.div 
                animate={{ x: ["-10%", "100%"] }}
                transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                className="absolute -top-2 left-0 w-full"
              >
                <ArrowRightLeft className="w-4 h-4 text-emerald-400 bg-slate-900 rounded-full" />
              </motion.div>
            </div>
          </div>

          {/* Bottom horizontal line to SOAR */}
          <div className="absolute left-8 bottom-0 right-0 border-b-2 border-dashed border-slate-500">
            <div className="absolute inset-0 w-full overflow-hidden">
              <motion.div 
                animate={{ x: ["-10%", "100%"] }}
                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                className="absolute -bottom-2 left-0 w-full"
              >
                <Zap className="w-4 h-4 text-purple-400 bg-slate-900 rounded-full" />
              </motion.div>
            </div>
          </div>
        </div>

        {/* Target Systems Stack */}
        <div className="flex flex-col justify-between h-64 z-10 w-72">
          
          {/* SIEM Block */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 }}
            className="h-28 bg-emerald-900/20 border border-emerald-500/40 rounded-xl p-4 flex flex-col justify-center shadow-lg"
          >
            <div className="flex items-center gap-3 mb-2 text-emerald-400">
              <Database className="w-5 h-5" />
              <span className="font-bold text-sm">SIEM Integration</span>
            </div>
            <div className="text-[11px] text-slate-300 leading-tight">
              Bi-directional sync with <span className="text-emerald-300">Splunk, QRadar, Wazuh</span>. Feed STIX 2.1 alerts directly into analyst queues.
            </div>
          </motion.div>

          {/* SOAR Block */}
          <motion.div 
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.6 }}
            className="h-28 bg-purple-900/20 border border-purple-500/40 rounded-xl p-4 flex flex-col justify-center shadow-lg"
          >
            <div className="flex items-center gap-3 mb-2 text-purple-400">
              <Activity className="w-5 h-5" />
              <span className="font-bold text-sm">SOAR Playbooks</span>
            </div>
            <div className="text-[11px] text-slate-300 leading-tight">
              Trigger automated <span className="text-purple-300">Cortex XSOAR / Splunk SOAR</span> responses based on autoMITRE's ML severity prediction.
            </div>
          </motion.div>

        </div>
      </div>
      
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1 }}
        className="flex items-center gap-2 mt-8 bg-slate-800/80 px-6 py-3 rounded-full border border-slate-700 text-xs text-slate-300 shadow-xl"
      >
        <ShieldCheck className="w-4 h-4 text-emerald-400" />
        Reduces MTTD & MTTR by executing generated mitigations instantaneously without human bottleneck.
      </motion.div>
    </div>
  );
}
