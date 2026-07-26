const STORAGE_KEY = 'super-recon:session'

// Sessão = { token, username, role } — um objeto só (não 3 chaves soltas)
// pra nunca ficar com token e usuário/papel dessincronizados no localStorage.
export function getSession() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY)) || null
  } catch {
    return null
  }
}

export function setSession(session) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session))
}

export function clearSession() {
  localStorage.removeItem(STORAGE_KEY)
}

export function getToken() {
  return getSession()?.token || ''
}

export function getUser() {
  const session = getSession()
  return session ? { username: session.username, role: session.role } : null
}

// True só logo após um login que usou a senha padrão semeada na instalação
// (ver backend: LoginResponse.must_change_password) — vem só na resposta do
// login, por isso fica guardado na sessão em vez de recalculado na hora.
export function getMustChangePassword() {
  return Boolean(getSession()?.mustChangePassword)
}

// Chamado depois de uma troca de senha bem-sucedida — tira o aviso sem
// precisar deslogar/logar de novo (o token da sessão atual continua válido:
// change-password preserva a sessão que fez a própria troca).
export function clearMustChangePassword() {
  const session = getSession()
  if (session) setSession({ ...session, mustChangePassword: false })
}
