import { useTranslation } from '../i18n/LanguageContext.jsx'
import { suffixLabel } from '../toolSchemas.js'

// Checklist de ferramentas da Fase 4 selecionáveis por scan ("Perfis de
// scan por execução") — usado no formulário de novo scan e no de
// recorrência (ClientDashboard.jsx), mesmo padrão de reaproveitamento do
// WordlistSelector.jsx. `value` nunca é null aqui: o pai popula a partir de
// GET /scan-defaults antes de renderizar o formulário.
export default function ToolChecklist({ value, onChange, tools }) {
  const { t } = useTranslation()

  function toggle(tool) {
    onChange(value.includes(tool) ? value.filter((t) => t !== tool) : [...value, tool])
  }

  return (
    <div className="tool-checklist">
      {tools.map((tool) => (
        <label key={tool} className="tool-checklist__item">
          <input type="checkbox" checked={value.includes(tool)} onChange={() => toggle(tool)} />
          {t(suffixLabel(tool))}
        </label>
      ))}
    </div>
  )
}
