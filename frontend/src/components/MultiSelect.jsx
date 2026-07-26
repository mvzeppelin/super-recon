import { useEffect, useRef, useState } from 'react'
import { useTranslation } from '../i18n/LanguageContext.jsx'

// Dropdown de múltipla escolha (checkbox por opção) — mesmo visual de um
// <select>, mas permite marcar mais de um valor pro mesmo filtro (ex: várias
// status de execução de uma vez, em vez de só uma por vez).
export default function MultiSelect({ options, values, onChange, placeholder, title }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return undefined
    function onClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [open])

  function toggleValue(value) {
    onChange(values.includes(value) ? values.filter((v) => v !== value) : [...values, value])
  }

  const summary = values.length === 0 ? t(placeholder) : values.join(', ')

  return (
    <div className="multi-select" ref={ref} title={title ? t(title) : undefined}>
      <button type="button" className="multi-select__trigger" onClick={() => setOpen((v) => !v)}>
        <span className="multi-select__summary">{summary}</span>
        <span className="multi-select__arrow">{open ? '▴' : '▾'}</span>
      </button>
      {open && (
        <div className="multi-select__menu">
          {options.map((opt) => (
            <label key={opt} className="multi-select__option">
              <input type="checkbox" checked={values.includes(opt)} onChange={() => toggleValue(opt)} />
              {opt}
            </label>
          ))}
          {values.length > 0 && (
            <button type="button" className="multi-select__clear" onClick={() => onChange([])}>
              {t('limpar seleção')}
            </button>
          )}
        </div>
      )}
    </div>
  )
}
