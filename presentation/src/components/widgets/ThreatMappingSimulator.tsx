import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Target, Database, Cpu, CheckCircle2 } from 'lucide-react';

export default function ThreatMappingSimulator() {
  const [isAnimating, setIsAnimating] = useState(false);
  const [stage, setStage] = useState(0);
  const [activeHover, setActiveHover] = useState<string | null>(null);

  const triggerSimulation = () => {
    if (isAnimating) return;
    setIsAnimating(true);
    setStage(1);
    
    setTimeout(() => setStage(2), 1500); // Parsing & Embeddings
    setTimeout(() => setStage(3), 3000); // RAG Search
    setTimeout(() => setStage(4), 4500); // Mapped
    
    setTimeout(() => {
      setIsAnimating(false);
      setStage(0);
    }, 7500);
  };

  return (
    <div className="w-full h-full p-8 flex flex-col items-center justify-center relative">
      <h3 className="text-xl font-mono text-center mb-8 text-slate-300 w-full border-b border-slate-700 pb-4">
        Live Simulator: Semantic Mapping
      </h3>

      <div className="flex-grow w-full flex flex-col items-center justify-center space-y-12">
        
        {/* Step 1: Input */}
        <button 
          onClick={triggerSimulation}
          className={`relative px-6 py-4 rounded-xl border transition-all duration-300 overflow-hidden ${stage === 0 ? 'bg-slate-800 border-cyan-500 hover:bg-slate-700 neon-glow-cyan cursor-pointer' : 'bg-slate-900 border-slate-800 opacity-50 cursor-default'}`}
        >
          {stage === 0 && (
            <motion.div 
              animate={{ rotate: 360 }}
              transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
              className="absolute -inset-10 bg-gradient-to-tr from-transparent via-cyan-500/10 to-transparent opacity-30"
            />
          )}
          <div className="flex items-center gap-4 relative z-10">
            <Target className="w-8 h-8 text-rose-400" />
            <div className="text-left">
              <p className="text-sm text-slate-400 font-mono">Raw Threat Data</p>
              <p className="text-lg font-bold text-slate-200">"mimikatz memory dump"</p>
            </div>
          </div>
          {stage === 0 && <span className="absolute -top-3 -right-3 flex h-6 w-6 z-20"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span><span className="relative inline-flex rounded-full h-6 w-6 bg-cyan-500 text-xs items-center justify-center text-white shadow-[0_0_10px_#22d3ee]">Click</span></span>}
        </button>

        {/* Step 2 & 3: Processing */}
        <div className="flex gap-16 relative mt-4">
          {/* Animated path */}
          {stage > 0 && (
            <motion.div 
              initial={{ height: 0 }}
              animate={{ height: 90 }}
              transition={{ duration: 1 }}
              className="absolute left-1/2 -top-16 w-1.5 bg-slate-800 border border-slate-700 -ml-[3px] rounded-full overflow-hidden shadow-inner"
            >
               {stage >= 1 && stage < 4 && (
                 <motion.div 
                   animate={{ y: [-40, 120] }}
                   transition={{ duration: 1.2, repeat: Infinity, ease: "linear" }}
                   className={`w-full h-10 rounded-full opacity-80 ${stage >= 3 ? 'bg-emerald-400 shadow-[0_0_15px_#34d399]' : 'bg-cyan-400 shadow-[0_0_15px_#22d3ee]'}`}
                 />
               )}
            </motion.div>
          )}

          <motion.div 
            onHoverStart={() => setActiveHover('cpu')}
            onHoverEnd={() => setActiveHover(null)}
            animate={{ opacity: stage >= 2 ? 1 : 0.3, scale: stage === 2 ? 1.1 : 1 }}
            className={`relative p-4 rounded-full border cursor-pointer ${stage === 2 ? 'border-cyan-400 bg-cyan-950/50 shadow-[0_0_15px_rgba(34,211,238,0.5)]' : 'border-slate-700 bg-slate-900 hover:border-slate-500'}`}
          >
            <Cpu className={`w-8 h-8 ${stage >= 2 ? 'text-cyan-400' : 'text-slate-600'}`} />
            
            <AnimatePresence>
              {activeHover === 'cpu' && (
                <motion.div 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 10 }}
                  className="absolute top-full left-1/2 -translate-x-1/2 mt-4 w-56 bg-slate-950 border border-slate-700 p-4 rounded-xl shadow-2xl z-50 pointer-events-none"
                >
                  <p className="text-xs text-cyan-400 font-mono mb-2 uppercase tracking-wider">Semantic Parser</p>
                  <p className="text-sm text-slate-300">Extracts semantics and severity scores using SecureBERT and Llama 3 models.</p>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>

          <motion.div 
            onHoverStart={() => setActiveHover('db')}
            onHoverEnd={() => setActiveHover(null)}
            animate={{ opacity: stage >= 3 ? 1 : 0.3, scale: stage === 3 ? 1.1 : 1 }}
            className={`relative p-4 rounded-full border cursor-pointer ${stage === 3 ? 'border-emerald-400 bg-emerald-950/50 shadow-[0_0_15px_rgba(52,211,153,0.5)]' : 'border-slate-700 bg-slate-900 hover:border-slate-500'}`}
          >
            <Database className={`w-8 h-8 ${stage >= 3 ? 'text-emerald-400' : 'text-slate-600'}`} />
            
            <AnimatePresence>
              {activeHover === 'db' && (
                <motion.div 
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 10 }}
                  className="absolute top-full left-1/2 -translate-x-1/2 mt-4 w-56 bg-slate-950 border border-slate-700 p-4 rounded-xl shadow-2xl z-50 pointer-events-none"
                >
                  <p className="text-xs text-emerald-400 font-mono mb-2 uppercase tracking-wider">ChromaDB RAG</p>
                  <p className="text-sm text-slate-300">Performs vector similarity searches to ground outputs in exact MITRE techniques.</p>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        </div>

        {/* Step 4: Output */}
        <motion.div 
          animate={{ 
            opacity: stage === 4 ? 1 : 0.2,
            y: stage === 4 ? 0 : 20
          }}
          className={`px-8 py-5 rounded-xl border ${stage === 4 ? 'bg-slate-800 border-emerald-500 neon-glow-emerald' : 'bg-slate-900 border-slate-800'}`}
        >
          <div className="flex items-center gap-4">
            <CheckCircle2 className="w-10 h-10 text-emerald-400" />
            <div className="text-left">
              <p className="text-sm text-slate-400 font-mono">Mapped ATT&CK Technique</p>
              <p className="text-2xl font-bold text-emerald-300 font-mono">T1003.001</p>
              <p className="text-sm text-slate-300">OS Credential Dumping: LSASS Memory</p>
            </div>
          </div>
        </motion.div>

      </div>
    </div>
  );
}
