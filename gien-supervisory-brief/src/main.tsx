import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import './index.css';
import { GovernanceProvider } from './context/GovernanceContext';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <GovernanceProvider>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </GovernanceProvider>
  </React.StrictMode>
);
