import { useState, useEffect, useCallback } from 'react';
import { slides } from './data/slides';
import SlideWrapper from './components/SlideWrapper';
import CyberBackground from './components/CyberBackground';
import { ChevronLeft, ChevronRight, ShieldAlert, Printer, Maximize, Minimize } from 'lucide-react';

function App() {
  const [currentSlideIndex, setCurrentSlideIndex] = useState(0);
  const [isExportMode, setIsExportMode] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(err => console.log(err));
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen();
      }
    }
  };

  const nextSlide = useCallback(() => {
    setCurrentSlideIndex((prev) => Math.min(prev + 1, slides.length - 1));
  }, []);

  const prevSlide = useCallback(() => {
    setCurrentSlideIndex((prev) => Math.max(prev - 1, 0));
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (isExportMode) return;
      if (e.key === 'ArrowRight' || e.key === ' ') {
        nextSlide();
      } else if (e.key === 'ArrowLeft') {
        prevSlide();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [nextSlide, prevSlide, isExportMode]);

  const slide = slides[currentSlideIndex];
  const progress = ((currentSlideIndex + 1) / slides.length) * 100;

  if (isExportMode) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-50 p-8 flex flex-col items-center">
        {/* Export Controls Header */}
        <div className="w-full max-w-7xl flex justify-between items-center mb-8 no-print bg-slate-900/80 p-4 rounded-xl border border-slate-800 backdrop-blur-sm">
          <div className="flex items-center gap-3 text-cyan-400">
            <ShieldAlert className="w-6 h-6" />
            <span className="font-mono font-bold text-sm tracking-wider uppercase">AutoMITRE Presentation Export</span>
          </div>
          <div className="flex gap-4">
            <button
              onClick={() => window.print()}
              className="flex items-center gap-2 px-5 py-2 bg-gradient-to-r from-cyan-600 to-emerald-500 hover:from-cyan-500 hover:to-emerald-400 text-slate-950 font-bold rounded-lg transition-all shadow-lg hover:shadow-cyan-500/20 cursor-pointer"
            >
              <Printer className="w-4 h-4" />
              Print / Save to PDF
            </button>
            <button
              onClick={() => setIsExportMode(false)}
              className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-all cursor-pointer"
            >
              Back to Presentation
            </button>
          </div>
        </div>

        {/* Print Layout container */}
        <div className="flex flex-col gap-12 w-full max-w-6xl items-center print-container">
          {slides.map((s, index) => (
            <div 
              key={s.id} 
              className="slide-page w-[1280px] h-[720px] bg-slate-950 border border-slate-800/80 rounded-xl relative flex items-center justify-center p-12 overflow-hidden shadow-2xl shrink-0"
            >
              <div className="absolute top-4 left-4 text-slate-700 font-mono text-[10px] tracking-widest uppercase opacity-30 select-none">
                AutoMITRE • Slide {String(index + 1).padStart(2, '0')}
              </div>
              <div className="w-full h-full transform scale-[0.85] origin-center">
                <SlideWrapper slide={s} />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen w-screen bg-slate-950 text-slate-50 overflow-hidden flex flex-col relative selection:bg-cyan-500/30">
      {/* Dynamic Cyber Matrix Background */}
      <CyberBackground />

      {/* Top Navbar */}
      <nav className="absolute top-0 w-full p-6 flex justify-between items-center z-50 pointer-events-none">
        <div className="flex items-center gap-3 text-cyan-400 pointer-events-auto">
          <ShieldAlert className="w-7 h-7" />
          <span className="font-mono font-bold tracking-wider text-sm uppercase">AutoMITRE</span>
        </div>
        <div className="flex items-center gap-4 pointer-events-auto">
          <button 
            onClick={toggleFullscreen}
            className="flex items-center gap-1.5 text-xs font-mono bg-slate-900/80 hover:bg-slate-800 text-slate-300 px-3 py-1.5 rounded-full border border-slate-800 transition-all cursor-pointer"
            title="Toggle Fullscreen"
          >
            {isFullscreen ? <Minimize className="w-3.5 h-3.5" /> : <Maximize className="w-3.5 h-3.5" />}
            <span className="mt-0.5">{isFullscreen ? 'Exit' : 'Fullscreen'}</span>
          </button>
          <button 
            onClick={() => setIsExportMode(true)}
            className="text-xs font-mono bg-cyan-950/80 hover:bg-cyan-900 text-cyan-400 px-3 py-1.5 rounded-full border border-cyan-800/50 transition-all hover:neon-glow-cyan cursor-pointer"
          >
            Export PDF
          </button>
          <div className="text-slate-400 font-mono text-sm bg-slate-900/80 px-4 py-1 rounded-full border border-slate-800">
            {String(currentSlideIndex + 1).padStart(2, '0')} / {slides.length}
          </div>
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
          className="p-3 rounded-full bg-slate-800/80 hover:bg-slate-700 text-slate-300 disabled:opacity-30 backdrop-blur-sm border border-slate-700 transition-all cursor-pointer"
        >
          <ChevronLeft className="w-6 h-6" />
        </button>
        <button 
          onClick={nextSlide}
          disabled={currentSlideIndex === slides.length - 1}
          className="p-3 rounded-full bg-slate-800/80 hover:bg-slate-700 text-cyan-400 disabled:opacity-30 backdrop-blur-sm border border-slate-700 transition-all hover:neon-glow-cyan cursor-pointer"
        >
          <ChevronRight className="w-6 h-6" />
        </button>
      </div>
    </div>
  );
}

export default App;
