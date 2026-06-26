import { useState } from 'react';
import { motion } from 'framer-motion';
import { Server, Database, BrainCircuit, Cpu, ArrowRight } from 'lucide-react';

const components = [
  { id: 'intake', icon: Server, label: 'Intake Router', color: 'text-blue-400', desc: 'Parses raw text, PCAP, HTML, and OSINT into standardized schemas.' },
  { id: 'securebert', icon: BrainCircuit, label: 'SecureBERT', color: 'text-indigo-400', desc: 'Domain-specific language model for extracting cyber semantics and severity scoring.' },
  { id: 'rag', icon: Database, label: 'ChromaDB (RAG)', color: 'text-emerald-400', desc: 'Local vector DB grounding LLM outputs to exact MITRE ATT&CK techniques.' },
  { id: 'llm', icon: Cpu, label: 'Hybrid LLM Engine', color: 'text-cyan-400', desc: 'Groq Cloud (Llama 3.1 & 3.3) with local Apple Metal fallback (Phi-3.5).' }
];

export default function InteractiveArchitecture() {
  const [activeId, setActiveId] = useState<string | null>(null);

  return (
    <div className="w-full h-full p-8 flex flex-col items-center justify-center relative">
      <h3 className="text-xl font-mono text-center mb-12 text-slate-300 w-full border-b border-slate-700 pb-4">Hover to inspect components</h3>
      
      <div className="flex items-center justify-center gap-6 w-full relative z-10">
        {components.map((comp, idx) => {
          const Icon = comp.icon;
          const isActive = activeId === comp.id;
          return (
            <div key={comp.id} className="flex items-center">
              <motion.div
                onHoverStart={() => setActiveId(comp.id)}
                onHoverEnd={() => setActiveId(null)}
                className={`relative flex flex-col items-center justify-center p-6 rounded-2xl cursor-pointer transition-all duration-300 ${isActive ? 'bg-slate-800 shadow-[0_0_20px_rgba(34,211,238,0.2)] border border-cyan-500/50' : 'bg-slate-900 border border-slate-800'}`}
                whileHover={{ scale: 1.05, y: -5 }}
              >
                <Icon className={`w-12 h-12 mb-3 ${comp.color}`} />
                <span className="font-mono text-sm text-slate-200">{comp.label}</span>
                
                {isActive && (
                  <motion.div 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 10 }}
                    className={`absolute top-full mt-4 w-64 bg-slate-950 border border-slate-700 p-4 rounded-xl shadow-2xl z-50 pointer-events-none ${
                      idx === 0 ? 'left-0' : idx === components.length - 1 ? 'right-0' : 'left-1/2 -translate-x-1/2'
                    }`}
                  >
                    <p className="text-sm text-slate-300">{comp.desc}</p>
                  </motion.div>
                )}
              </motion.div>
              
              {idx < components.length - 1 && (
                <div className="mx-4 w-12 h-1.5 bg-slate-800/80 relative overflow-hidden rounded-full shadow-inner border border-slate-900">
                  <motion.div
                    animate={{ x: [-20, 60] }}
                    transition={{ duration: 1.5, repeat: Infinity, ease: "linear", delay: idx * 0.5 }}
                    className="absolute top-0 left-0 w-6 h-full bg-cyan-400 shadow-[0_0_10px_#22d3ee] rounded-full opacity-80"
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
