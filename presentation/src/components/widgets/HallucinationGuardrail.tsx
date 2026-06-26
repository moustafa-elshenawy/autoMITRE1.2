import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bot, Database, AlertOctagon, CheckCircle2, ShieldX, ShieldCheck } from 'lucide-react';

export default function HallucinationGuardrail() {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setStep((prev) => (prev + 1) % 4);
    }, 2500);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="w-full h-full p-8 flex flex-col items-center justify-center relative bg-slate-900/50">
      <h3 className="text-xl font-mono text-center mb-10 text-slate-300 w-full border-b border-slate-700 pb-4">
        Hallucination Guardrails
      </h3>

      <div className="flex w-full justify-between gap-8 h-64 relative">
        {/* Left Side: Standard LLM */}
        <div className="w-1/2 flex flex-col items-center border-r border-slate-700/50 pr-8">
          <div className="text-rose-400 font-mono text-sm mb-4">Standard LLM</div>
          <div className="bg-slate-800 p-4 rounded-xl border border-slate-700 shadow-lg relative">
            <Bot className="w-10 h-10 text-slate-400" />
            {step >= 1 && (
              <motion.div 
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                className="absolute top-full mt-6 left-1/2 -translate-x-1/2 w-48 bg-rose-950/80 border border-rose-500/50 p-4 rounded-xl shadow-[0_0_15px_rgba(244,63,94,0.3)]"
              >
                <div className="flex items-center gap-2 mb-2 text-rose-400">
                  <ShieldX className="w-5 h-5" />
                  <span className="font-bold text-sm">Hallucination</span>
                </div>
                <div className="font-mono text-lg text-rose-200">T9999</div>
                <div className="text-xs text-rose-300/70 mt-1">Non-existent technique</div>
              </motion.div>
            )}
          </div>
          {step >= 1 && (
            <motion.div 
              initial={{ height: 0 }}
              animate={{ height: 24 }}
              className="w-1 bg-gradient-to-b from-slate-700 to-rose-500 absolute top-[110px] left-[23%]"
            />
          )}
        </div>

        {/* Right Side: AutoMITRE */}
        <div className="w-1/2 flex flex-col items-center pl-8">
          <div className="text-emerald-400 font-mono text-sm mb-4">AutoMITRE RAG</div>
          <div className="bg-slate-800 p-4 rounded-xl border border-cyan-500/50 shadow-[0_0_15px_rgba(34,211,238,0.2)] relative z-10">
            <Bot className="w-10 h-10 text-cyan-400" />
          </div>

          {step >= 1 && (
            <motion.div 
              initial={{ height: 0 }}
              animate={{ height: 32 }}
              className="w-1 bg-cyan-500 absolute top-[110px] left-[77%]"
            />
          )}

          {step >= 2 && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              className="mt-8 bg-slate-800 p-4 rounded-xl border border-emerald-500/50 shadow-[0_0_15px_rgba(52,211,153,0.2)] relative z-10"
            >
              <Database className="w-8 h-8 text-emerald-400 mx-auto" />
              <div className="text-xs text-emerald-300 mt-2 font-mono">ChromaDB</div>
            </motion.div>
          )}

          {step >= 2 && (
            <motion.div 
              initial={{ height: 0 }}
              animate={{ height: 24 }}
              className="w-1 bg-emerald-500 absolute top-[210px] left-[77%]"
            />
          )}

          {step >= 3 && (
            <motion.div 
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              className="absolute top-[230px] left-[55%] w-56 bg-emerald-950/80 border border-emerald-500/50 p-4 rounded-xl shadow-[0_0_15px_rgba(52,211,153,0.3)] z-20"
            >
              <div className="flex items-center gap-2 mb-2 text-emerald-400">
                <ShieldCheck className="w-5 h-5" />
                <span className="font-bold text-sm">Grounded Truth</span>
              </div>
              <div className="font-mono text-lg text-emerald-200">T1003.001</div>
              <div className="text-xs text-emerald-300/70 mt-1">OS Credential Dumping</div>
            </motion.div>
          )}
        </div>
      </div>
    </div>
  );
}
