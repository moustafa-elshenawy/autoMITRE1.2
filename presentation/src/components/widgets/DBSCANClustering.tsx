import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

// Generate some random dots
const NUM_DOTS = 50;
const generateDots = () => {
  return Array.from({ length: NUM_DOTS }).map((_, i) => ({
    id: i,
    initialX: Math.random() * 100,
    initialY: Math.random() * 100,
    // Assign to one of 3 clusters
    cluster: i % 3,
    // Cluster centers
    targetX: i % 3 === 0 ? 20 : i % 3 === 1 ? 80 : 50,
    targetY: i % 3 === 0 ? 30 : i % 3 === 1 ? 20 : 80,
  }));
};

const dots = generateDots();

export default function DBSCANClustering() {
  const [clustered, setClustered] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setClustered((prev) => !prev);
    }, 4000); // toggle every 4 seconds
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="w-full h-full p-8 flex flex-col items-center justify-center relative bg-slate-900/50">
      <h3 className="text-xl font-mono text-center mb-6 text-slate-300 w-full border-b border-slate-700 pb-4">
        DBSCAN Threat Campaign Clustering
      </h3>

      <div className="w-full flex-grow relative bg-slate-950 rounded-xl border border-slate-800 shadow-inner overflow-hidden">
        {/* Radar grid lines */}
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:20px_20px]"></div>

        {/* Legend */}
        <div className="absolute top-4 left-4 flex flex-col gap-2 z-20 bg-slate-900/80 p-3 rounded-lg border border-slate-700 backdrop-blur-sm">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-cyan-400 shadow-[0_0_8px_#22d3ee]"></div>
            <span className="text-xs font-mono text-slate-300">Ransomware Gangs</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-rose-400 shadow-[0_0_8px_#f43f5e]"></div>
            <span className="text-xs font-mono text-slate-300">APT Nation States</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399]"></div>
            <span className="text-xs font-mono text-slate-300">Botnet Operators</span>
          </div>
        </div>

        {/* The Dots */}
        {dots.map((dot) => {
          let color = "bg-slate-500 shadow-none";
          if (clustered) {
            color = dot.cluster === 0 
              ? "bg-cyan-400 shadow-[0_0_10px_#22d3ee]" 
              : dot.cluster === 1 
                ? "bg-rose-400 shadow-[0_0_10px_#f43f5e]" 
                : "bg-emerald-400 shadow-[0_0_10px_#34d399]";
          }

          // Add a little scatter to the targets so they don't all stack perfectly
          const scatterX = (Math.random() - 0.5) * 15;
          const scatterY = (Math.random() - 0.5) * 15;

          return (
            <motion.div
              key={dot.id}
              initial={false}
              animate={{
                left: `${clustered ? dot.targetX + scatterX : dot.initialX}%`,
                top: `${clustered ? dot.targetY + scatterY : dot.initialY}%`,
              }}
              transition={{ duration: 2, ease: "easeInOut" }}
              className={`absolute w-3 h-3 rounded-full transition-colors duration-1000 z-10 ${color}`}
            />
          );
        })}

        {/* Overlay showing status */}
        <div className="absolute bottom-4 right-4 z-20">
          <div className={`px-4 py-2 font-mono text-xs rounded-full border transition-colors duration-500 ${clustered ? 'bg-cyan-900/50 border-cyan-400 text-cyan-200 shadow-[0_0_10px_#22d3ee]' : 'bg-slate-800 border-slate-600 text-slate-400'}`}>
            {clustered ? 'CLUSTERS IDENTIFIED' : 'ANALYZING NOISE...'}
          </div>
        </div>
      </div>
    </div>
  );
}
