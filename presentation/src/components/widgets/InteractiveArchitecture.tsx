import { useState } from 'react';
import { motion } from 'framer-motion';
import { MonitorPlay, Server, Database } from 'lucide-react';

const components = [
  { id: 'presentation', icon: MonitorPlay, label: 'Presentation Layer', color: 'text-cyan-400', desc: 'React 19 SPA (Vite/Tailwind) optimized for real-time SOC visual rendering.' },
  { id: 'application', icon: Server, label: 'Application Layer', color: 'text-emerald-400', desc: 'FastAPI Python backend orchestrating AI models, routers, and data processing.' },
  { id: 'data', icon: Database, label: 'Data Layer', color: 'text-indigo-400', desc: 'SQLite persistence, ChromaDB vector store, and static JSON corpora.' }
];

export default function InteractiveArchitecture() {
  const [activeId, setActiveId] = useState<string | null>(null);

  return (
    <div className="w-full h-full p-8 flex flex-col relative">
      <h3 className="text-xl font-mono text-center mb-8 text-slate-300 w-full border-b border-slate-700 pb-4">Hover to inspect architecture tiers</h3>
      
      <div className="flex flex-col items-start justify-center pl-12 flex-grow w-full relative z-10">
        {components.map((comp, idx) => {
          const Icon = comp.icon;
          const isActive = activeId === comp.id;
          return (
            <div key={comp.id} className="flex flex-col items-center w-72 relative">
              <motion.div
                onHoverStart={() => setActiveId(comp.id)}
                onHoverEnd={() => setActiveId(null)}
                className={`relative flex items-center justify-start p-6 rounded-2xl cursor-pointer transition-all duration-300 w-full ${isActive ? 'bg-slate-800 shadow-[0_0_20px_rgba(34,211,238,0.2)] border border-cyan-500/50' : 'bg-slate-900 border border-slate-800'}`}
                whileHover={{ scale: 1.05 }}
              >
                <Icon className={`w-12 h-12 mr-5 ${comp.color} shrink-0`} />
                <span className="font-bold text-lg text-slate-200">{comp.label}</span>
                
                {isActive && (
                  <motion.div 
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    className="absolute left-[110%] top-1/2 -translate-y-1/2 w-80 bg-slate-950 border border-slate-700 p-5 rounded-xl shadow-[0_0_30px_rgba(0,0,0,0.8)] z-50 pointer-events-none"
                  >
                    <p className="text-sm text-slate-300 leading-relaxed">{comp.desc}</p>
                  </motion.div>
                )}
              </motion.div>
              
              {idx < components.length - 1 && (
                <div className="my-4 h-12 w-1.5 bg-slate-800/80 relative overflow-hidden rounded-full shadow-inner border border-slate-900">
                  <motion.div
                    animate={{ y: [-20, 60], opacity: [0, 1, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity, ease: "linear", delay: idx * 0.5 }}
                    className="absolute top-0 left-0 w-full h-6 bg-cyan-400 shadow-[0_0_10px_#22d3ee] rounded-full"
                  />
                  <motion.div
                    animate={{ y: [60, -20], opacity: [0, 1, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity, ease: "linear", delay: (idx * 0.5) + 0.75 }}
                    className="absolute top-0 left-0 w-full h-6 bg-emerald-400 shadow-[0_0_10px_#34d399] rounded-full"
                  />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
