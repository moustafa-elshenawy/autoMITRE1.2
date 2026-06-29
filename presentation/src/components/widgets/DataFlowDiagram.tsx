import { motion } from 'framer-motion';

export default function DataFlowDiagram() {
  const boxClass = "text-[11px] font-mono px-3 py-2 rounded-md border shadow-lg relative z-10 bg-slate-900/80 backdrop-blur-sm text-center flex items-center justify-center";
  const lineClass = "absolute bg-gradient-to-b from-cyan-500 to-emerald-500 w-0.5 z-0";
  const arrowClass = "w-0 h-0 border-l-[4px] border-l-transparent border-r-[4px] border-r-transparent border-t-[6px] border-t-emerald-500 absolute -bottom-1 left-[-3px]";

  const nodeVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: (custom: number) => ({
      opacity: 1,
      y: 0,
      transition: { delay: custom * 0.3, duration: 0.5, type: "spring", stiffness: 100 }
    })
  };

  const lineVariants = {
    hidden: { height: 0, opacity: 0 },
    visible: (custom: number) => ({
      height: "100%",
      opacity: 1,
      transition: { delay: custom * 0.3, duration: 0.5, ease: "easeInOut" }
    })
  };

  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 relative">
      <p className="text-[12px] font-mono text-slate-400 uppercase tracking-widest mb-4">Architectural Data Flow</p>

      {/* Raw Input */}
      <motion.div custom={0} variants={nodeVariants} initial="hidden" animate="visible" className={`${boxClass} w-64 border-slate-600 text-slate-200 mb-6`}>
        Raw Threat Intel / Logs
      </motion.div>

      <div className="flex w-full max-w-lg justify-between relative mb-6">
        {/* Left Branch - 3-Layer Pipeline */}
        <div className="flex flex-col items-center gap-4 w-1/2 relative">
          <div className="text-[10px] uppercase text-cyan-400 font-bold mb-1">Three-Layer Pipeline</div>
          
          <motion.div custom={1} variants={nodeVariants} initial="hidden" animate="visible" className={`${boxClass} w-48 border-cyan-500/50 text-cyan-100`}>
            Layer 1: Llama-3.2-3B Extractor
          </motion.div>
          
          <motion.div custom={2} variants={nodeVariants} initial="hidden" animate="visible" className={`${boxClass} w-48 border-cyan-500/50 text-cyan-100`}>
            Layer 2: all-mpnet Retriever
          </motion.div>
          
          <motion.div custom={3} variants={nodeVariants} initial="hidden" animate="visible" className={`${boxClass} w-48 border-cyan-500/50 text-cyan-100`}>
            Layer 3: Logic Gatekeeper
          </motion.div>
        </div>

        {/* Right Branch - Deep Learning Pipeline */}
        <div className="flex flex-col items-center gap-4 w-1/2 relative">
          <div className="text-[10px] uppercase text-purple-400 font-bold mb-1">Deep-Learning Pipeline</div>
          
          <motion.div custom={1.5} variants={nodeVariants} initial="hidden" animate="visible" className={`${boxClass} w-48 border-purple-500/50 text-purple-100`}>
            SecureBERT Backbone
          </motion.div>
          
          <motion.div custom={2.5} variants={nodeVariants} initial="hidden" animate="visible" className={`${boxClass} w-48 border-purple-500/50 text-purple-100`}>
            all-mpnet Bi-Encoder Reranker
          </motion.div>
        </div>
      </div>

      {/* Convergence */}
      <motion.div custom={4} variants={nodeVariants} initial="hidden" animate="visible" className={`${boxClass} w-56 border-emerald-500/50 text-emerald-100 mb-6 mt-2`}>
        XGBoost Severity Predictor
      </motion.div>

      {/* Output */}
      <motion.div custom={5} variants={nodeVariants} initial="hidden" animate="visible" className={`${boxClass} w-64 border-amber-500/50 text-amber-100`}>
        Final Threat Analysis Report
      </motion.div>
      
      {/* Decorative background nodes to indicate flow connection */}
      <motion.div 
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2, duration: 1 }}
        className="absolute inset-0 pointer-events-none flex flex-col items-center justify-center z-0"
      >
        <svg width="100%" height="100%" className="absolute inset-0 z-0">
          <defs>
            <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.5" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.5" />
            </linearGradient>
            <linearGradient id="purpleGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#a855f7" stopOpacity="0.5" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.5" />
            </linearGradient>
          </defs>
          {/* Paths connecting nodes */}
          <path d="M 285 100 L 170 140 L 170 290 L 285 330" fill="transparent" stroke="url(#cyanGrad)" strokeWidth="1.5" strokeDasharray="4 4" className="animate-pulse" />
          <path d="M 285 100 L 400 140 L 400 240 L 285 330" fill="transparent" stroke="url(#purpleGrad)" strokeWidth="1.5" strokeDasharray="4 4" className="animate-pulse" />
          <path d="M 285 370 L 285 410" fill="transparent" stroke="#10b981" strokeWidth="1.5" strokeDasharray="4 4" />
        </svg>
      </motion.div>
    </div>
  );
}
