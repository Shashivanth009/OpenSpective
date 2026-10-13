// Auth context for OpenSpective frontend
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import * as api from './api.ts';

interface AuthContextType {
  user: api.User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string, displayName?: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<api.User | null>(null);
  const [loading, setLoading] = useState(true);

  const loadUser = useCallback(async () => {
    const token = api.getToken();
    if (!token) { setLoading(false); return; }
    try {
      const { user } = await api.getMe();
      setUser(user);
    } catch {
      api.setToken(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadUser(); }, [loadUser]);

  const login = async (email: string, password: string) => {
    const result = await api.login(email, password);
    api.setToken(result.token);
    setUser(result.user);
  };

  const signup = async (email: string, password: string, displayName?: string) => {
    const result = await api.signup(email, password, displayName);
    api.setToken(result.token);
    setUser(result.user);
  };

  const logout = async () => {
    try { await api.logout(); } catch { /* ignore */ }
    api.setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
