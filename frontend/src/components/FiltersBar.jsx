import MultiSelect from './MultiSelect.jsx'
import { useTranslation } from '../i18n/LanguageContext.jsx'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const JOB_STATUSES = ['queued', 'running', 'ok', 'error', 'cancelled']

export default function FiltersBar({
  q,
  onQChange,
  toolOptions = [],
  toolValue = '',
  onToolChange,
  scanOptions = [],
  scanValue = '',
  onScanChange,
  showSeverity = false,
  severityValue = '',
  onSeverityChange,
  showStatus = false,
  statusValues = [],
  onStatusChange,
}) {
  const { t } = useTranslation()
  return (
    <div className="filters-bar">
      <input
        type="search"
        placeholder={t('Buscar…')}
        value={q}
        onChange={(e) => onQChange(e.target.value)}
        className="filters-bar__search"
      />
      {toolOptions.length > 1 && (
        <select value={toolValue} onChange={(e) => onToolChange(e.target.value)}>
          <option value="">{t('Todas as origens')}</option>
          {toolOptions.map((tool) => (
            <option key={tool} value={tool}>
              {tool}
            </option>
          ))}
        </select>
      )}
      {scanOptions.length > 1 && (
        <select value={scanValue} onChange={(e) => onScanChange(e.target.value)} title={t('Filtrar por execução de scan')}>
          <option value="">{t('Todos os scans')}</option>
          {scanOptions.map((s) => (
            <option key={s.scan_id} value={s.scan_id}>
              {s.label}
            </option>
          ))}
        </select>
      )}
      {showSeverity && (
        <select value={severityValue} onChange={(e) => onSeverityChange(e.target.value)}>
          <option value="">{t('Todas as severidades')}</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      )}
      {showStatus && (
        <MultiSelect
          options={JOB_STATUSES}
          values={statusValues}
          onChange={onStatusChange}
          placeholder="Todos os status"
        />
      )}
    </div>
  )
}
