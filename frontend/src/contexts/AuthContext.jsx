import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Check if token exists in localStorage on load
        const storedToken = localStorage.getItem('token');
        const storedUser = localStorage.getItem('user');

        if (storedToken && storedUser) {
            setToken(storedToken);
            setUser(JSON.parse(storedUser));

            // Refresh profile data from server in background
            fetch('http://localhost:8000/api/users/profile', {
                headers: { 'Authorization': `Bearer ${storedToken}` }
            }).then(res => {
                if (res.ok) return res.json();
                if (res.status === 401) {
                    logout(); // Token is invalid, clear it
                }
            }).then(freshUser => {
                if (freshUser) {
                    setUser(freshUser);
                    localStorage.setItem('user', JSON.stringify(freshUser));
                }
            }).catch(() => { }); // Silently fail if server is offline
        }
        setLoading(false);
    }, []);

    const login = (newUser, newToken) => {
        setUser(newUser);
        setToken(newToken);
        localStorage.setItem('token', newToken);
        localStorage.setItem('user', JSON.stringify(newUser));
    };

    const logout = () => {
        setUser(null);
        setToken(null);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
    };

    /** Merge partial profile updates into the stored user without full re-login. */
    const updateUser = (partialUser) => {
        const updated = { ...user, ...partialUser };
        setUser(updated);
        localStorage.setItem('user', JSON.stringify(updated));
    };

    return (
        <AuthContext.Provider value={{ user, token, login, logout, updateUser, isAuthenticated: !!token }}>
            {!loading && children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};
