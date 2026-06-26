import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Server, Zap, AlertTriangle, CheckCircle } from 'lucide-react';

export default function HardwareMonitor() {
  const [glitch, setGlitch] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setGlitch(true);
      setTimeout(() => setGlitch(false), 200);
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="w-full h-full p-8 flex flex-col items-center justify-center relative bg-slate-900/50">
      <h3 className="text-xl font-mono text-center mb-10 text-slate-300 w-full border-b border-slate-700 pb-4">
        Hardware Resource Monitor
      </h3>

      <div className="w-full flex flex-col gap-10">
        {/* Top Bar: Massive 70B Model */}
        <div className="w-full bg-slate-800 rounded-2xl p-6 border border-slate-700 shadow-xl relative overflow-hidden">
          <div className="flex justify-between items-center mb-4">
            <div className="flex items-center gap-3">
              <Server className="w-6 h-6 text-rose-400" />
              <span className="font-mono text-slate-200">Standard 70B LLM</span>
            </div>
            <div className="text-rose-400 font-mono font-bold flex items-center gap-2">
              <AlertTriangle className={`w-5 h-5 ${glitch ? 'opacity-100' : 'opacity-50'}`} />
              <span>OOM / Kernel Panic</span>
            </div>
          </div>
          
          <div className="w-full h-8 bg-slate-900 rounded-full overflow-hidden relative">
            <div className="absolute top-0 bottom-0 left-1/4 w-0.5 bg-slate-600 z-10"></div>
            <div className="absolute top-0 bottom-0 left-1/2 w-0.5 bg-slate-600 z-10"></div>
            <div className="absolute top-0 bottom-0 left-3/4 w-0.5 bg-slate-600 z-10"></div>
            
            {/* The RAM bar overflowing */}
            <motion.div 
              initial={{ width: 0 }}
              animate={{ width: "120%" }}
              transition={{ duration: 2, ease: "easeOut" }}
              className={`h-full bg-rose-500 rounded-full shadow-[0_0_15px_rgba(244,63,94,0.6)] ${glitch ? 'opacity-80' : 'opacity-100'}`}
            />
          </div>
          <div className="flex justify-between text-xs text-slate-400 font-mono mt-2">
            <span>0GB</span>
            <span>Max Device Memory (8GB / 16GB)</span>
            <span className="text-rose-400 font-bold">Req: ~35GB+</span>
          </div>
        </div>

        {/* Bottom Bar: Quantized Phi-3.5 */}
        <div className="w-full bg-slate-800 rounded-2xl p-6 border border-cyan-500/30 shadow-xl relative overflow-hidden">
          <div className="flex justify-between items-center mb-4">
            <div className="flex items-center gap-3">
              <Zap className="w-6 h-6 text-emerald-400" />
              <span className="font-mono text-slate-200">AutoMITRE: Quantized Phi-3.5</span>
            </div>
            <div className="text-emerald-400 font-mono font-bold flex items-center gap-2">
              <CheckCircle className="w-5 h-5" />
              <span>Stable (Metal/MPS)</span>
            </div>
          </div>
          
          <div className="w-full h-8 bg-slate-900 rounded-full overflow-hidden relative">
            <div className="absolute top-0 bottom-0 left-1/4 w-0.5 bg-slate-600 z-10"></div>
            <div className="absolute top-0 bottom-0 left-1/2 w-0.5 bg-slate-600 z-10"></div>
            <div className="absolute top-0 bottom-0 left-3/4 w-0.5 bg-slate-600 z-10"></div>
            
            <motion.div 
              initial={{ width: 0 }}
              animate={{ width: "25%" }}
              transition={{ duration: 1.5, ease: "easeOut", delay: 0.5 }}
              className="h-full bg-emerald-400 rounded-full shadow-[0_0_15px_rgba(52,211,153,0.6)]"
            />
          </div>
          <div className="flex justify-between text-xs text-slate-400 font-mono mt-2">
            <span>0GB</span>
            <span>4GB</span>
            <span>8GB</span>
            <span>16GB</span>
          </div>
        </div>
      </div>
    </div>
  );
}
