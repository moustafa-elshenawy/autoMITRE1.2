import { motion } from 'framer-motion';

export default function CyberBackground() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none z-0">
      {/* Dynamic Cyber Grid */}
      <div className="absolute inset-0 cyber-grid opacity-20"></div>

      {/* Animated Scanline Overlay */}
      <div className="absolute top-0 left-0 right-0 h-32 bg-gradient-to-b from-transparent via-cyan-500/10 to-transparent animate-scanline"></div>

      {/* Glowing Orbs for ambiance */}
      <motion.div
        animate={{
          scale: [1, 1.2, 1],
          opacity: [0.1, 0.2, 0.1],
        }}
        transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
        className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-900/40 rounded-full blur-[120px]"
      />
      <motion.div
        animate={{
          scale: [1, 1.5, 1],
          opacity: [0.1, 0.15, 0.1],
        }}
        transition={{ duration: 12, repeat: Infinity, ease: "easeInOut", delay: 2 }}
        className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] bg-emerald-900/30 rounded-full blur-[150px]"
      />
    </div>
  );
}
