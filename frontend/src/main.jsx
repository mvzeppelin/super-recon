import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.jsx'
import LoginGate from './components/LoginGate.jsx'
import { LanguageProvider } from './i18n/LanguageContext.jsx'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <LanguageProvider>
      <LoginGate>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </LoginGate>
    </LanguageProvider>
  </React.StrictMode>,
)
