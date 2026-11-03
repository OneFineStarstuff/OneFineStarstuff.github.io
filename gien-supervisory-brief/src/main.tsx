import React from 'react';
import ReactDOM from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import App from './App';
import './index.css';
import { GovernanceProvider } from './context/GovernanceContext';
import { ToastProvider } from './context/ToastContext';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <HashRouter>
      <GovernanceProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </GovernanceProvider>
    </HashRouter>
  </React.StrictMode>
);
