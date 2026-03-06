import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { User, Lock, Mail, UserPlus, ShieldAlert, Shield, ShieldCheck } from 'lucide-react';

const Register = () => {
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const { login } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        setIsLoading(true);

        try {
            // 1. Register
            const regResponse = await fetch('http://localhost:8000/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password }),
            });

            if (!regResponse.ok) {
                const errData = await regResponse.json();
                throw new Error(errData.detail || 'Registration failed');
            }

            // 2. Automatically login after successful registration
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            const loginResponse = await fetch('http://localhost:8000/api/auth/token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData,
            });

            if (!loginResponse.ok) throw new Error('Auto-login failed. Please log in manually.');

            const data = await loginResponse.json();

            const userResponse = await fetch('http://localhost:8000/api/auth/me', {
                headers: { 'Authorization': `Bearer ${data.access_token}` }
            });

            if (!userResponse.ok) throw new Error('Failed to fetch user profile');

            const userData = await userResponse.json();
            login(userData, data.access_token);
            navigate('/');

        } catch (err) {
            if (Array.isArray(err.message)) setError(err.message[0].msg)
            else setError(err.message || 'Registration failed');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-glow" />

            <div className="auth-content">
                <div className="auth-card">

                    <div className="auth-header">
                        <div className="auth-logo">
                            <ShieldCheck size={32} color="#0ea5e9" strokeWidth={2.5} />
                            <h1>AutoMITRE</h1>
                        </div>
                        <h2 className="auth-title">Create Instance</h2>
                        <p className="auth-subtitle">Register for a new secure workspace environment</p>
                    </div>

                    {error && (
                        <div className="auth-error">
                            <ShieldAlert size={20} className="shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="auth-group">
                            <label className="auth-label">Username</label>
                            <div className="auth-input-wrapper">
                                <div className="auth-input-icon">
                                    <User size={16} />
                                </div>
                                <input
                                    type="text"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    className="auth-input"
                                    placeholder="Choose an identifier"
                                    required
                                />
                            </div>
                        </div>

                        <div className="auth-group">
                            <label className="auth-label">Email</label>
                            <div className="auth-input-wrapper">
                                <div className="auth-input-icon">
                                    <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                    </svg>
                                </div>
                                <input
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    className="auth-input"
                                    placeholder="operator@system.io"
                                    required
                                />
                            </div>
                        </div>

                        <div className="auth-group">
                            <label className="auth-label">Password</label>
                            <div className="auth-input-wrapper">
                                <div className="auth-input-icon">
                                    <Lock size={16} />
                                </div>
                                <input
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="auth-input"
                                    style={{ letterSpacing: '0.2em' }}
                                    placeholder="••••••••"
                                    required
                                />
                            </div>
                        </div>

                        <div className="auth-group">
                            <label className="auth-label">Confirm Password</label>
                            <div className="auth-input-wrapper">
                                <div className="auth-input-icon">
                                    <Lock size={16} />
                                </div>
                                <input
                                    type="password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    className="auth-input"
                                    style={{ letterSpacing: '0.2em' }}
                                    placeholder="••••••••"
                                    required
                                />
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={isLoading}
                            className="auth-button"
                        >
                            {isLoading ? (
                                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" style={{ marginRight: '8px' }} />
                            ) : null}
                            {isLoading ? 'Provisioning...' : 'Initialize Account'}
                        </button>
                    </form>

                    <div className="auth-footer">
                        <Link to="/login" className="auth-link">
                            Already possess clearance? Sign In
                        </Link>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Register;
