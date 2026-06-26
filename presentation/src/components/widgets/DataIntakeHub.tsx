import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FileText, Network, Code, Globe, FileJson } from 'lucide-react';

const sources = [
  { id: 'text', icon: FileText, label: 'Raw Threat Reports', color: 'text-rose-400', glow: 'shadow-[0_0_15px_#f43f5e]', beam: 'bg-rose-400' },
  { id: 'pcap', icon: Network, label: 'PCAP Files', color: 'text-indigo-400', glow: 'shadow-[0_0_15px_#818cf8]', beam: 'bg-indigo-400' },
  { id: 'html', icon: Code, label: 'Scraped HTML', color: 'text-amber-400', glow: 'shadow-[0_0_15px_#fbbf24]', beam: 'bg-amber-400' },
  { id: 'osint', icon: Globe, label: 'OSINT Feeds', color: 'text-emerald-400', glow: 'shadow-[0_0_15px_#34d399]', beam: 'bg-emerald-400' },
];

export default function DataIntakeHub() {
  const [activeSource, setActiveSource] = useState<string | null>(null);

  return (
    <div className="w-full h-full p-8 flex flex-col items-center justify-center relative bg-slate-900/50 overflow-hidden">
      <h3 className="text-xl font-mono text-center mb-16 text-slate-300 w-full border-b border-slate-700 pb-4">
        Interactive Intake Router
      </h3>

      <div className="relative w-full max-w-md aspect-square flex items-center justify-center">
        
        {/* Central Hub */}
        <motion.div 
          animate={{ scale: activeSource ? 1.1 : 1 }}
          className={`absolute z-20 p-6 rounded-2xl border transition-colors duration-300 flex flex-col items-center justify-center ${activeSource ? 'bg-cyan-950 border-cyan-400 shadow-[0_0_30px_rgba(34,211,238,0.4)]' : 'bg-slate-800 border-slate-600'}`}
        >
          <FileJson className={`w-12 h-12 mb-2 ${activeSource ? 'text-cyan-400' : 'text-slate-400'}`} />
          <span className="font-mono text-xs text-slate-200">Standardized</span>
          <span className="font-mono text-xs text-slate-200">Schema (JSON)</span>
        </motion.div>

        {/* Orbiting Sources */}
        {sources.map((source, index) => {
          const angle = (index * (360 / sources.length)) * (Math.PI / 180);
          const radius = 160;
          const x = Math.cos(angle) * radius;
          const y = Math.sin(angle) * radius;
          
          const isActive = activeSource === source.id;

          return (
            <div key={source.id} className="absolute z-30" style={{ transform: `translate(${x}px, ${y}px)` }}>
              <motion.div
                onHoverStart={() => setActiveSource(source.id)}
                onHoverEnd={() => setActiveSource(null)}
                animate={{ y: [0, -10, 0] }}
                transition={{ duration: 3, repeat: Infinity, delay: index * 0.5, ease: "easeInOut" }}
                className={`relative p-4 rounded-full cursor-pointer border transition-all duration-300 bg-slate-900 ${isActive ? `border-${source.color.split('-')[1]}-400 ${source.glow} scale-110` : 'border-slate-700 hover:border-slate-500'}`}
              >
                <source.icon className={`w-8 h-8 ${isActive ? source.color : 'text-slate-500'}`} />
                
                <AnimatePresence>
                  {isActive && (
                    <motion.div 
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: 10 }}
                      className="absolute top-full left-1/2 -translate-x-1/2 mt-3 whitespace-nowrap bg-slate-950 border border-slate-700 px-3 py-1.5 rounded-lg shadow-xl font-mono text-xs text-slate-300"
                    >
                      {source.label}
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>

              {/* Laser Beam connecting to center */}
              <AnimatePresence>
                {isActive && (
                  <motion.div
                    initial={{ opacity: 0, scaleX: 0 }}
                    animate={{ opacity: 1, scaleX: 1 }}
                    exit={{ opacity: 0, scaleX: 0 }}
                    transition={{ duration: 0.2 }}
                    style={{
                      transformOrigin: '0 50%',
                      transform: `rotate(${Math.atan2(-y, -x)}rad)`,
                      width: `${radius - 50}px`
                    }}
                    className={`absolute top-1/2 left-1/2 h-1 -mt-0.5 rounded-full z-10 ${source.beam} shadow-[0_0_10px_currentColor]`}
                  />
                )}
              </AnimatePresence>
            </div>
          );
        })}

      </div>
    </div>
  );
}
