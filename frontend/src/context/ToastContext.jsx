import { createContext, useCallback, useContext, useMemo, useState } from 'react';

const ToastContext = createContext(null);

let toastCounter = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const pushToast = useCallback(
    ({ title, description = '', variant = 'info', duration = 5000 }) => {
      const id = `toast-${++toastCounter}`;
      setToasts((prev) => [...prev.slice(-4), { id, title, description, variant }]);
      if (duration > 0) {
        setTimeout(() => {
          dismissToast(id);
        }, duration);
      }
      return id;
    },
    [dismissToast]
  );

  const value = useMemo(
    () => ({
      toasts,
      pushToast,
      dismissToast,
      success: (title, description) => pushToast({ title, description, variant: 'success' }),
      error: (title, description) => pushToast({ title, description, variant: 'error', duration: 7000 }),
      warning: (title, description) => pushToast({ title, description, variant: 'warning', duration: 6000 }),
      info: (title, description) => pushToast({ title, description, variant: 'info' }),
    }),
    [toasts, pushToast, dismissToast]
  );

  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>;
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return ctx;
}
