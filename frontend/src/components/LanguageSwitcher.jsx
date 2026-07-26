import { useTranslation } from '../i18n/LanguageContext.jsx'

export default function LanguageSwitcher() {
  const { lang, setLang } = useTranslation()

  return (
    <div className="language-switcher">
      <button
        type="button"
        className={`language-switcher__flag${lang === 'pt' ? ' language-switcher__flag--active' : ''}`}
        onClick={() => setLang('pt')}
        title="Português"
        aria-label="Português"
      >
        🇧🇷
      </button>
      <button
        type="button"
        className={`language-switcher__flag${lang === 'en' ? ' language-switcher__flag--active' : ''}`}
        onClick={() => setLang('en')}
        title="English"
        aria-label="English"
      >
        🇬🇧
      </button>
    </div>
  )
}
