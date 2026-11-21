import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import ReportPanel from './ReportPanel';
import reportWebVitals from './reportWebVitals';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
    <div style={{ backgroundColor: '#0a0f1e', padding: '0 20px 40px' }}>
      <ReportPanel />
    </div>
  </React.StrictMode>
);

reportWebVitals();
