import { useState, useEffect, useCallback } from 'react';
import { slides } from './data/slides';
import SlideWrapper from './components/SlideWrapper';
import CyberBackground from './components/CyberBackground';
import { ChevronLeft, ChevronRight, ShieldAlert } from 'lucide-react';

function App() {
  const [currentSlideIndex, setCurrentSlideIndex] = useState(0);

  const nextSlide = useCallback(() => {
    setCurrentSlideIndex((prev) => Math.min(prev + 1, slides.length - 1));
  }, []);

  const prevSlide = useCallback(() => {
    setCurrentSlideIndex((prev) => Math.max(prev - 1, 0));
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === ' ') {
        nextSlide();
      } else if (e.key === 'ArrowLeft') {
        prevSlide();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [nextSlide, prevSlide]);

  const slide = slides[currentSlideIndex];
  const progress = ((currentSlideIndex + 1) / slides.length) * 100;

  return (
    <div className="h-screen w-screen bg-slate-950 text-slate-50 overflow-hidden flex flex-col relative selection:bg-cyan-500/30">
      {/* Dynamic Cyber Matrix Background */}
      <CyberBackground />

      {/* Top Navbar */}
      <nav className="absolute top-0 w-full p-6 flex justify-between items-center z-50 pointer-events-none">
        <div className="flex items-center gap-3 text-cyan-400">
          <ShieldAlert className="w-7 h-7" />
          <span className="font-mono font-bold tracking-wider text-sm uppercase">AutoMITRE</span>
        </div>
        <div className="text-slate-400 font-mono text-sm bg-slate-900/80 px-4 py-1 rounded-full border border-slate-800">
          {String(currentSlideIndex + 1).padStart(2, '0')} / {slides.length}
        </div>
      </nav>

      {/* Main Slide Content */}
      <main className="flex-grow flex items-center justify-center p-12 relative w-full h-full">
        <SlideWrapper key={slide.id} slide={slide} />
      </main>

      {/* Progress Bar */}
      <div className="absolute bottom-0 w-full h-1.5 bg-slate-900 z-50">
        <div 
          className="h-full bg-gradient-to-r from-cyan-500 to-emerald-400 transition-all duration-500 ease-out shadow-[0_0_10px_rgba(34,211,238,0.5)]"
          style={{ width: `${progress}%` }}
        />
      </div>

      {/* Controls Overlay */}
      <div className="absolute bottom-8 right-8 z-50 flex gap-4">
        <button 
          onClick={prevSlide}
          disabled={currentSlideIndex === 0}
          className="p-3 rounded-full bg-slate-800/80 hover:bg-slate-700 text-slate-300 disabled:opacity-30 backdrop-blur-sm border border-slate-700 transition-all"
        >
          <ChevronLeft className="w-6 h-6" />
        </button>
        <button 
          onClick={nextSlide}
          disabled={currentSlideIndex === slides.length - 1}
          className="p-3 rounded-full bg-slate-800/80 hover:bg-slate-700 text-cyan-400 disabled:opacity-30 backdrop-blur-sm border border-slate-700 transition-all hover:neon-glow-cyan"
        >
          <ChevronRight className="w-6 h-6" />
        </button>
      </div>
    </div>
  );
}

export default App;
