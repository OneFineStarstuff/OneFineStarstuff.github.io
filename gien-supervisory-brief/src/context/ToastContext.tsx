import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';

export type ToastSeverity = 'INFO' | 'SUCCESS' | 'ELEVATED' | 'CRITICAL';

export interface Toast {
  id: string;
  severity: ToastSeverity;
  message: string;
}

interface ToastContextValue {
  toasts: Toast[];
  pushToast: (severity: ToastSeverity, message: string) => void;
  dismissToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counter = useRef(0);

  const dismissToast = useCallback((id: string) => {
    setToasts((list) => list.filter((t) => t.id !== id));
  }, []);

  const pushToast = useCallback(
    (severity: ToastSeverity, message: string) => {
      counter.current += 1;
      const id = `TOAST-${Date.now()}-${counter.current}`;
      setToasts((list) => [...list.slice(-4), { id, severity, message }]);
      window.setTimeout(() => dismissToast(id), 7000);
    },
    [dismissToast]
  );

  const value = useMemo(() => ({ toasts, pushToast, dismissToast }), [toasts, pushToast, dismissToast]);
  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>;
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}
