import { Link, Route, Routes } from 'react-router-dom'
import AssetDetail from './pages/AssetDetail.jsx'
import AuditLogPage from './pages/AuditLogPage.jsx'
import ClientDashboard from './pages/ClientDashboard.jsx'
import ClientsPage from './pages/ClientsPage.jsx'
import MyAccountPage from './pages/MyAccountPage.jsx'
import ScanCompare from './pages/ScanCompare.jsx'
import SettingsPage from './pages/SettingsPage.jsx'
import ToolFindings from './pages/ToolFindings.jsx'
import UsersPage from './pages/UsersPage.jsx'
import { api } from './api.js'
import { clearSession, getMustChangePassword, getUser } from './auth.js'
import LanguageSwitcher from './components/LanguageSwitcher.jsx'
import WorkerStatus from './components/WorkerStatus.jsx'
import { useTranslation } from './i18n/LanguageContext.jsx'

export default function App() {
  const { t } = useTranslation()
  const user = getUser()
  const mustChangePassword = getMustChangePassword()

  function handleLogout() {
    // Não bloqueia o logout local se a chamada falhar (rede fora, sessão já
    // expirada no servidor etc.) — o usuário quer sair da tela de qualquer jeito.
    api.logout().catch(() => {}).finally(() => {
      clearSession()
      window.location.reload()
    })
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <Link to="/" className="app-title">
          <img src="/super-recon-logo-256.png" alt="" className="app-title__logo" />
          super-recon
        </Link>
        <div className="app-header__right">
          <WorkerStatus />
          <LanguageSwitcher />
          {user && (
            <>
              {user.role === 'admin' && (
                <>
                  <Link to="/users" className="link-button">
                    {t('Usuários')}
                  </Link>
                  <Link to="/audit-log" className="link-button">
                    {t('Log de auditoria')}
                  </Link>
                  <Link to="/settings" className="link-button">
                    {t('Configurações')}
                  </Link>
                </>
              )}
              <Link to="/account" className="link-button">
                {t('Minha conta')}
              </Link>
              <button type="button" className="link-button" onClick={handleLogout}>
                {t('sair')}
              </button>
            </>
          )}
        </div>
      </header>
      {mustChangePassword && (
        <div className="password-warning-banner">
          {t('Você está usando a senha padrão de instalação. Troque agora em "Minha conta".')}{' '}
          <Link to="/account">{t('Trocar senha')}</Link>
        </div>
      )}
      <main className="app-main">
        <Routes>
          <Route path="/" element={<ClientsPage />} />
          <Route path="/clients/:client" element={<ClientDashboard />} />
          <Route path="/clients/:client/compare" element={<ScanCompare />} />
          <Route path="/clients/:client/asset" element={<AssetDetail />} />
          <Route path="/clients/:client/:suffix" element={<ToolFindings />} />
          <Route path="/account" element={<MyAccountPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/audit-log" element={<AuditLogPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  )
}
