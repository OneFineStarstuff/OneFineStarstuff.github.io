import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { Role, Layer } from './types';

interface RoleCtx {
  role: Role; layer: Layer;
  setRole: (r: Role) => void;
  setLayer: (l: Layer) => void;
}
const RC = createContext<RoleCtx | null>(null);

const defaultLayerFor = (role: Role): Layer =>
  role === 'engineer' || role === 'g-sifi' ? 'engineering' : 'executive';

export function RoleProvider({ children }: { children: ReactNode }) {
  const [params, setParams] = useSearchParams();
  const role = (params.get('role') as Role) || 'regulator';
  const layer = (params.get('layer') as Layer) || defaultLayerFor(role);
  const setRole = (r: Role) => {
    const p = new URLSearchParams(params);
    p.set('role', r); p.set('layer', defaultLayerFor(r));
    setParams(p, { replace: true });
  };
  const setLayer = (l: Layer) => {
    const p = new URLSearchParams(params);
    p.set('layer', l);
    setParams(p, { replace: true });
  };
  return <RC.Provider value={{ role, layer, setRole, setLayer }}>{children}</RC.Provider>;
}
export function useRole() {
  const v = useContext(RC);
  if (!v) throw new Error('RoleProvider missing');
  return v;
}

interface ThemeCtx { theme: 'light' | 'dark'; toggle: () => void; }
const TC = createContext<ThemeCtx | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
  }, [theme]);
  return <TC.Provider value={{ theme, toggle: () => setTheme(t => t === 'light' ? 'dark' : 'light') }}>{children}</TC.Provider>;
}
export function useTheme() {
  const v = useContext(TC);
  if (!v) throw new Error('ThemeProvider missing');
  return v;
}

export interface Toast { id: string; severity: 'GREEN' | 'AMBER' | 'RED' | 'CRITICAL'; title: string; body?: string; }
interface ToastCtx { push: (t: Omit<Toast, 'id'>) => void; toasts: Toast[]; dismiss: (id: string) => void; }
const ToC = createContext<ToastCtx | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = (t: Omit<Toast, 'id'>) => {
    const id = Math.random().toString(36).slice(2);
    setToasts(x => [...x, { ...t, id }]);
    const dur = t.severity === 'GREEN' || t.severity === 'AMBER' ? 6000 : 15000;
    setTimeout(() => setToasts(x => x.filter(y => y.id !== id)), dur);
  };
  const dismiss = (id: string) => setToasts(x => x.filter(t => t.id !== id));
  return <ToC.Provider value={{ push, toasts, dismiss }}>{children}</ToC.Provider>;
}
export function useToast() {
  const v = useContext(ToC);
  if (!v) throw new Error('ToastProvider missing');
  return v;
}
