import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { en } from './translations.js'

const STORAGE_KEY = 'super-recon:lang'
const DICTS = { en }

const LanguageContext = createContext(null)

function interpolate(text, vars) {
  if (!vars) return text
  return Object.entries(vars).reduce((acc, [k, v]) => acc.replaceAll(`{{${k}}}`, v), text)
}

export function LanguageProvider({ children }) {
  const [lang, setLang] = useState(() => localStorage.getItem(STORAGE_KEY) || 'pt')

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, lang)
  }, [lang])

  const value = useMemo(() => {
    const dict = DICTS[lang] || {}
    // Chave = texto original em português; sem tradução (ou lang="pt"),
    // cai no próprio texto — por isso não existe um dicionário "pt" separado.
    const t = (key, vars) => interpolate(dict[key] ?? key, vars)
    return { lang, setLang, t }
  }, [lang])

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>
}

export function useTranslation() {
  const ctx = useContext(LanguageContext)
  if (!ctx) throw new Error('useTranslation deve ser usado dentro de um LanguageProvider')
  return ctx
}
