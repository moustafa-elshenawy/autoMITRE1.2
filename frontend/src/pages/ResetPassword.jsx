import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, Link, useSearchParams } from 'react-router-dom';

const ResetPassword = () => {
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [tick, setTick] = useState(true);
    const canvasRef = useRef(null);
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const token = searchParams.get('token');

    useEffect(() => {
        if (!token) {
            setError('No reset token found in the URL. Please request a new link.');
        }
    }, [token]);

    // Blinking cursor
    useEffect(() => {
        const t = setInterval(() => setTick(v => !v), 530);
        return () => clearInterval(t);
    }, []);

    // Green particle network
    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        let w = canvas.width = window.innerWidth;
        let h = canvas.height = window.innerHeight;
        const pts = Array.from({ length: 55 }, () => ({
            x: Math.random() * w, y: Math.random() * h,
            vx: (Math.random() - 0.5) * 0.3, vy: (Math.random() - 0.5) * 0.3,
            r: Math.random() * 1.1 + 0.3
        }));
        let raf;
        const draw = () => {
            ctx.clearRect(0, 0, w, h);
            pts.forEach(p => {
                p.x += p.vx; p.y += p.vy;
                if (p.x < 0 || p.x > w) p.vx *= -1;
                if (p.y < 0 || p.y > h) p.vy *= -1;
                ctx.beginPath();
                ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(0,255,65,0.45)';
                ctx.fill();
            });
            pts.forEach((a, i) => pts.slice(i + 1).forEach(b => {
                const d = Math.hypot(a.x - b.x, a.y - b.y);
                if (d < 110) {
                    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
                    ctx.strokeStyle = `rgba(0,255,65,${0.12 * (1 - d / 110)})`;
                    ctx.lineWidth = 0.5; ctx.stroke();
                }
            }));
            raf = requestAnimationFrame(draw);
        };
        draw();
        const onR = () => { w = canvas.width = window.innerWidth; h = canvas.height = window.innerHeight; };
        window.addEventListener('resize', onR);
        return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', onR); };
    }, []);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setMessage('');
        
        if (!token) {
            setError('Missing reset token.');
            return;
        }

        if (password !== confirmPassword) {
            setError('Passwords do not match.');
            return;
        }

        setIsLoading(true);
        try {
            const backendUrl = localStorage.getItem('backendUrl') || 'http://127.0.0.1:8001';
            const response = await fetch(`${backendUrl}/api/auth/reset-password`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, new_password: password }),
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || 'Request failed');
            setMessage(data.message + " Redirecting to login...");
            setTimeout(() => {
                navigate('/login');
            }, 3000);
        } catch (err) {
            setError(err.message || 'Request failed');
        } finally {
            setIsLoading(false);
        }
    };

    const inputStyle = {
        width: '100%', boxSizing: 'border-box', position: 'relative', zIndex: 10,
        background: 'rgba(0,255,65,0.03)',
        border: '1px solid rgba(0,255,65,0.2)',
        padding: '13px 16px 13px 44px',
        fontFamily: 'JetBrains Mono, monospace', fontSize: 13,
        color: '#fff', outline: 'none',
        transition: 'border-color 0.2s, box-shadow 0.2s',
        letterSpacing: '0.02em'
    };

    return (
        <div style={{ position: 'relative', minHeight: '100vh', background: '#020202', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: "'JetBrains Mono', monospace", overflow: 'hidden' }}>
            <canvas ref={canvasRef} style={{ position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none' }} />
            <div style={{ position: 'fixed', inset: 0, zIndex: 1, pointerEvents: 'none', backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.18) 2px, rgba(0,0,0,0.18) 4px)', opacity: 0.6 }} />
            <div style={{ position: 'fixed', top: '20%', right: '10%', width: 600, height: 600, background: 'radial-gradient(circle, rgba(0,255,65,0.04) 0%, transparent 65%)', borderRadius: '50%', pointerEvents: 'none', zIndex: 0 }} />
            <div style={{ position: 'fixed', bottom: '15%', left: '5%', width: 400, height: 400, background: 'radial-gradient(circle, rgba(0,255,65,0.03) 0%, transparent 65%)', borderRadius: '50%', pointerEvents: 'none', zIndex: 0 }} />

            <button
                onClick={() => navigate('/login')}
                style={{ position: 'fixed', top: 20, left: 32, zIndex: 10, display: 'flex', alignItems: 'center', gap: 8, background: 'transparent', border: 'none', color: 'rgba(255,255,255,0.35)', cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, letterSpacing: '0.08em', transition: 'color 0.2s' }}
                onMouseEnter={e => e.currentTarget.style.color = '#00ff41'}
                onMouseLeave={e => e.currentTarget.style.color = 'rgba(255,255,255,0.35)'}
            >
                &lt;_ BACK TO LOGIN
            </button>

            <div style={{ position: 'relative', zIndex: 2, width: '100%', maxWidth: 420, padding: '0 24px' }}>
                <div style={{ textAlign: 'center', marginBottom: 36 }}>
                    <div style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, fontSize: 22, letterSpacing: '0.04em', marginBottom: 8 }}>
                        <span style={{ color: '#00ff41', textShadow: '0 0 12px rgba(0,255,65,0.7)' }}>A</span>
                        <span style={{ color: '#fff' }}>uto</span>
                        <span style={{ color: '#00ff41', textShadow: '0 0 12px rgba(0,255,65,0.7)' }}>MITRE</span>
                    </div>
                    <div style={{ fontSize: 11, color: 'rgba(0,255,65,0.5)', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
                        &gt;_ THREAT INTELLIGENCE PLATFORM {tick ? '█' : ' '}
                    </div>
                </div>

                <div style={{ background: 'rgba(0,255,65,0.02)', border: '1px solid rgba(0,255,65,0.15)', padding: '40px 36px', backdropFilter: 'blur(12px)' }}>
                    <div style={{ marginBottom: 28 }}>
                        <div style={{ fontSize: 10, color: 'rgba(0,255,65,0.4)', letterSpacing: '0.12em', marginBottom: 10 }}>&gt;_ // CREDENTIAL UPDATE</div>
                        <h1 style={{ fontFamily: "'Archivo Black', sans-serif", fontSize: 24, fontWeight: 900, color: '#00ff41', letterSpacing: '-0.02em', textTransform: 'uppercase', margin: '0 0 6px', textShadow: '0 0 20px rgba(0,255,65,0.3)' }}>
                            SET NEW PASS
                        </h1>
                        <p style={{ fontFamily: 'Archivo, sans-serif', fontSize: 13, color: 'rgba(255,255,255,0.45)', margin: 0 }}>
                            Enter your new passphrase
                        </p>
                    </div>

                    {error && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(220,38,38,0.08)', border: '1px solid rgba(220,38,38,0.3)', padding: '11px 14px', marginBottom: 20, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#f87171', letterSpacing: '0.02em' }}>
                            <span>[!]</span> {error}
                        </div>
                    )}
                    
                    {message && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(0,255,65,0.08)', border: '1px solid rgba(0,255,65,0.3)', padding: '11px 14px', marginBottom: 20, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: '#00ff41', letterSpacing: '0.02em' }}>
                            <span>[+]</span> {message}
                        </div>
                    )}

                    <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                        <div>
                            <label style={{ display: 'block', fontSize: 10, fontWeight: 600, color: 'rgba(0,255,65,0.5)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8 }}>
                                [01] NEW PASSPHRASE
                            </label>
                            <div style={{ position: 'relative' }}>
                                <span style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none', color: 'rgba(0,255,65,0.4)', fontSize: 12 }}>#_</span>
                                <input
                                    type="password" value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    placeholder="••••••••••••"
                                    required
                                    disabled={!token || message !== ''}
                                    style={inputStyle}
                                    onFocus={e => { e.target.style.borderColor = '#00ff41'; e.target.style.boxShadow = '0 0 12px rgba(0,255,65,0.15)'; }}
                                    onBlur={e => { e.target.style.borderColor = 'rgba(0,255,65,0.2)'; e.target.style.boxShadow = 'none'; }}
                                />
                            </div>
                        </div>

                        <div>
                            <label style={{ display: 'block', fontSize: 10, fontWeight: 600, color: 'rgba(0,255,65,0.5)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8 }}>
                                [02] CONFIRM PASSPHRASE
                            </label>
                            <div style={{ position: 'relative' }}>
                                <span style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none', color: 'rgba(0,255,65,0.4)', fontSize: 12 }}>#_</span>
                                <input
                                    type="password" value={confirmPassword}
                                    onChange={e => setConfirmPassword(e.target.value)}
                                    placeholder="••••••••••••"
                                    required
                                    disabled={!token || message !== ''}
                                    style={inputStyle}
                                    onFocus={e => { e.target.style.borderColor = '#00ff41'; e.target.style.boxShadow = '0 0 12px rgba(0,255,65,0.15)'; }}
                                    onBlur={e => { e.target.style.borderColor = 'rgba(0,255,65,0.2)'; e.target.style.boxShadow = 'none'; }}
                                />
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={isLoading || !token || message !== ''}
                            style={{ width: '100%', background: (isLoading || !token || message !== '') ? 'rgba(0,255,65,0.3)' : '#00ff41', border: '1px solid #00ff41', padding: '14px', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, fontSize: 13, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#000', cursor: (isLoading || !token || message !== '') ? 'not-allowed' : 'pointer', boxShadow: '0 0 20px rgba(0,255,65,0.3)', transition: 'all 0.2s', marginTop: 6 }}
                            onMouseEnter={e => { if (!isLoading && token && message === '') { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#00ff41'; e.currentTarget.style.boxShadow = '0 0 30px rgba(0,255,65,0.5)'; } }}
                            onMouseLeave={e => { if (token && message === '') { e.currentTarget.style.background = '#00ff41'; e.currentTarget.style.color = '#000'; e.currentTarget.style.boxShadow = '0 0 20px rgba(0,255,65,0.3)'; } }}
                        >
                            {isLoading ? '[ SAVING... ]' : '[ SAVE PASS />]'}
                        </button>
                    </form>
                </div>
            </div>

            <style>{`
                input::placeholder { color: rgba(255,255,255,0.18); font-family: 'JetBrains Mono', monospace; }
                input:-webkit-autofill { -webkit-box-shadow: 0 0 0 30px #020202 inset !important; -webkit-text-fill-color: #fff !important; }
            `}</style>
        </div>
    );
};

export default ResetPassword;
