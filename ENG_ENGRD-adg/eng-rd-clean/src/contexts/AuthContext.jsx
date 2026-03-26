// src/contexts/AuthContext.jsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import { loginAdmin, verifyToken, logoutAdmin } from '../services/apiService';
import { publicClient } from '../utils/axiosConfig';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
};

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState(localStorage.getItem('adminToken'));

  useEffect(() => {
    const checkAuth = async () => {
      const savedToken = localStorage.getItem('adminToken');
      if (savedToken) {
        try {
          const response = await verifyToken(savedToken);
          if (response.success) {
            setToken(savedToken);
            setUser(response.user);
            setIsAuthenticated(true);
          } else {
            localStorage.removeItem('adminToken');
            setToken(null); setUser(null); setIsAuthenticated(false);
          }
        } catch {
          localStorage.removeItem('adminToken');
          setToken(null); setUser(null); setIsAuthenticated(false);
        }
      }
      setLoading(false);
    };
    checkAuth();
  }, []);

  // Step 1: username + password
  const login = async (username, password) => {
    try {
      const response = await loginAdmin(username, password);
      if (response.success && response.requiresTwoFactor) {
        // Return partial token so Login.jsx can show the 2FA step
        return { success: true, requiresTwoFactor: true, partialToken: response.partialToken };
      }
      if (response.success) {
        localStorage.setItem('adminToken', response.token);
        setToken(response.token);
        setUser(response.user);
        setIsAuthenticated(true);
        return { success: true };
      }
      return { success: false, message: response.message };
    } catch (error) {
      return { success: false, message: error.response?.data?.message || 'Erreur de connexion' };
    }
  };

  // Step 2: TOTP or recovery code
  const verifyTwoFactor = async (partialToken, totpToken, recoveryCode) => {
    try {
      const { data } = await publicClient.post('/api/auth/2fa/verify', {
        partialToken,
        token: totpToken || undefined,
        recoveryCode: recoveryCode || undefined
      });
      if (data.success) {
        localStorage.setItem('adminToken', data.token);
        setToken(data.token);
        setUser(data.user);
        setIsAuthenticated(true);
        return { success: true, warning: data.warning };
      }
      return { success: false, message: data.message, locked: data.locked, attemptsLeft: data.attemptsLeft };
    } catch (error) {
      const d = error.response?.data || {};
      return { success: false, message: d.message || 'Erreur de vérification', locked: d.locked, attemptsLeft: d.attemptsLeft };
    }
  };

  const logout = async () => {
    try { await logoutAdmin(); } catch {}
    localStorage.removeItem('adminToken');
    setToken(null); setUser(null); setIsAuthenticated(false);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, loading, login, verifyTwoFactor, logout, token }}>
      {children}
    </AuthContext.Provider>
  );
};
