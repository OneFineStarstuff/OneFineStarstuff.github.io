import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { CheckCircle2, Info, X, XCircle } from "lucide-react";

type ToastTone = "info" | "success" | "error";
interface ToastItem {
  id: number;
  message: string;
  tone: ToastTone;
}
interface ToastApi {
  notify: (message: string, tone?: ToastTone) => void;
}
const ToastContext = createContext<ToastApi | null>(null);

export function useToast(): ToastApi {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider.");
  return context;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const notify = useCallback((message: string, tone: ToastTone = "info") => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setItems(current => [...current, { id, message, tone }]);
    window.setTimeout(() => setItems(current => current.filter(item => item.id !== id)), 4500);
  }, []);
  const dismiss = (id: number) => setItems(current => current.filter(item => item.id !== id));

  return (
    <ToastContext.Provider value={{ notify }}>
      {children}
      <div className="toast-stack" aria-live="polite" aria-atomic="false">
        {items.map(item => {
          const Icon = item.tone === "success" ? CheckCircle2 : item.tone === "error" ? XCircle : Info;
          return (
            <div className={`toast toast-${item.tone}`} key={item.id} role="status">
              <Icon size={18} aria-hidden="true" />
              <span>{item.message}</span>
              <button className="icon-button toast-dismiss" onClick={() => dismiss(item.id)} aria-label="Dismiss notification">
                <X size={15} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
