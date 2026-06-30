import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Braces, Share2, Server } from 'lucide-react';

export default function STIXTree() {
  const [nodes, setNodes] = useState<number>(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setNodes((prev) => {
        if (prev >= 4) return 0;
        return prev + 1;
      });
    }, 1500);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="w-full h-full p-8 flex flex-col items-center justify-center relative bg-slate-900/50">
      <h3 className="text-xl font-mono text-center mb-10 text-slate-300 w-full border-b border-slate-700 pb-4">
        STIX 2.1 Export & Splunk Interoperability
      </h3>

      <div className="flex w-full justify-center gap-12 items-center h-64">
        
        {/* Left: STIX JSON Build */}
        <div className="flex flex-col items-center">
          <div className="bg-slate-800 p-4 rounded-xl border border-slate-700 mb-6 flex items-center gap-3">
            <Braces className="w-8 h-8 text-cyan-400" />
            <span className="font-mono text-cyan-100 font-bold">STIX_2.1_Bundle</span>
          </div>
          
          <div className="flex gap-4 relative">
            {/* Connection lines */}
            <div className="absolute top-[-24px] left-[15%] w-[70%] h-6 border-t-2 border-l-2 border-r-2 border-slate-600 rounded-t-lg"></div>

            <AnimatePresence>
              {nodes >= 1 && (
                <motion.div 
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-slate-900 border border-slate-700 p-3 rounded-lg text-xs font-mono text-slate-400 flex flex-col items-center"
                >
                  <span className="text-emerald-400">Attack_Pattern</span>
                  <span>T1003.001</span>
                </motion.div>
              )}
            </AnimatePresence>
            <AnimatePresence>
              {nodes >= 2 && (
                <motion.div 
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-slate-900 border border-slate-700 p-3 rounded-lg text-xs font-mono text-slate-400 flex flex-col items-center"
                >
                  <span className="text-rose-400">Threat_Actor</span>
                  <span>APT29</span>
                </motion.div>
              )}
            </AnimatePresence>
            <AnimatePresence>
              {nodes >= 3 && (
                <motion.div 
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-slate-900 border border-slate-700 p-3 rounded-lg text-xs font-mono text-slate-400 flex flex-col items-center"
                >
                  <span className="text-indigo-400">Malware</span>
                  <span>Mimikatz</span>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Right: Export to Splunk */}
        <div className="flex items-center gap-6">
          <motion.div 
            animate={{ 
              x: nodes === 4 ? [0, 40, 0] : 0,
              opacity: nodes === 4 ? [0.2, 1, 0.2] : 0.2
            }}
            transition={{ duration: 1 }}
            className="text-cyan-500 flex items-center"
          >
            <Share2 className="w-8 h-8" />
          </motion.div>

          <motion.div 
            animate={{ 
              scale: nodes === 4 ? [1, 1.1, 1] : 1,
              borderColor: nodes === 4 ? '#34d399' : '#334155'
            }}
            transition={{ duration: 0.5 }}
            className={`bg-slate-800 p-6 rounded-2xl border-2 flex flex-col items-center justify-center w-40 h-40 shadow-2xl relative overflow-hidden`}
          >
            <Server className={`w-12 h-12 mb-2 ${nodes === 4 ? 'text-emerald-400' : 'text-slate-500'}`} />
            <span className="font-bold text-slate-200">Enterprise SIEM</span>
            <span className="text-xs text-slate-400 mt-1">(Splunk / Elastic)</span>
            
            {nodes === 4 && (
              <motion.div 
                initial={{ opacity: 0 }}
                animate={{ opacity: [0, 1, 0] }}
                transition={{ duration: 1 }}
                className="absolute inset-0 bg-emerald-500/20"
              />
            )}
          </motion.div>
        </div>

      </div>
    </div>
  );
}
