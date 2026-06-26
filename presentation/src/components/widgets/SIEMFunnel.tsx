import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Filter, AlertTriangle, ShieldAlert } from 'lucide-react';

export default function SIEMFunnel() {
  const [clogged, setClogged] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setClogged((prev) => !prev);
    }, 4000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="w-full h-full p-8 flex flex-col items-center justify-center relative bg-slate-900/50">
      <h3 className="text-xl font-mono text-center mb-8 text-slate-300 w-full border-b border-slate-700 pb-4">
        SIEM Ingestion Bottleneck
      </h3>

      <div className="relative w-64 h-80 flex flex-col items-center justify-start mt-4">
        
        {/* Massive incoming logs */}
        <div className="flex justify-center gap-2 mb-4 w-full px-8 relative h-16">
          {Array.from({ length: 15 }).map((_, i) => (
            <motion.div
              key={i}
              initial={{ y: -50, opacity: 0 }}
              animate={{ 
                y: clogged ? 20 : [ -50, 80 ], 
                opacity: clogged ? 1 : [0, 1, 0] 
              }}
              transition={{ 
                duration: clogged ? 0.5 : 1.5, 
                repeat: clogged ? 0 : Infinity, 
                delay: i * 0.1,
                ease: "linear"
              }}
              className="w-2 h-6 bg-slate-600 rounded-sm"
              style={{ x: (Math.random() - 0.5) * 40 }}
            />
          ))}
        </div>

        {/* The Funnel */}
        <div className="relative z-10 w-full flex flex-col items-center">
          <div className="w-full h-16 bg-slate-800/80 border-t-2 border-l-2 border-r-2 border-slate-600 rounded-t-xl backdrop-blur-sm" style={{ clipPath: 'polygon(0 0, 100% 0, 80% 100%, 20% 100%)' }}>
             <Filter className="w-8 h-8 text-slate-400 absolute top-2 left-1/2 -translate-x-1/2" />
          </div>
          <div className="w-2/5 h-24 bg-slate-800/80 border-l-2 border-r-2 border-slate-600 relative overflow-hidden backdrop-blur-sm">
            {clogged && (
              <motion.div 
                initial={{ height: 0 }}
                animate={{ height: "100%" }}
                transition={{ duration: 1 }}
                className="absolute bottom-0 w-full bg-rose-500/80"
              />
            )}
          </div>
          <div className="w-2/5 h-4 bg-slate-800/80 border-b-2 border-l-2 border-r-2 border-slate-600 rounded-b-xl backdrop-blur-sm"></div>
        </div>

        {/* Clog Warning Overlay */}
        <AnimatePresence>
          {clogged && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-20 bg-rose-950/90 border-2 border-rose-500 px-6 py-4 rounded-2xl shadow-[0_0_30px_rgba(244,63,94,0.5)] flex flex-col items-center"
            >
              <AlertTriangle className="w-10 h-10 text-rose-400 mb-2 animate-pulse" />
              <span className="font-bold text-rose-200 font-mono text-center">ANALYST FATIGUE</span>
              <span className="text-xs text-rose-400 text-center mt-1">Too much raw data</span>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Clean Output */}
        <AnimatePresence>
          {!clogged && (
            <motion.div 
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 10 }}
              exit={{ opacity: 0 }}
              className="mt-4 flex flex-col items-center"
            >
              <ShieldAlert className="w-8 h-8 text-emerald-400 mb-2" />
              <span className="font-mono text-xs text-emerald-400">Processed Alert</span>
            </motion.div>
          )}
        </AnimatePresence>

      </div>
    </div>
  );
}
