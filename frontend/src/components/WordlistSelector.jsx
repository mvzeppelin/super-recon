import { useTranslation } from '../i18n/LanguageContext.jsx'

// Seletor de perfil de wordlist do gobuster (common/big/custom) + escolha/
// upload de wordlist customizada — usado nos 3 formulários que disparam um
// scan (ClientsPage, novo scan e recorrência em ClientDashboard). Extraído
// porque as 3 cópias divergiam de forma inconsistente (rótulo, presença do
// upload) sem nenhum motivo real de negócio.
export default function WordlistSelector({
  value,
  onChange,
  customWordlistId,
  onCustomWordlistIdChange,
  wordlists,
  showLabel = true,
  showUpload = true,
  uploadFile,
  onUploadFileChange,
  onUpload,
  uploading,
  disabledReason,
}) {
  const { t } = useTranslation()

  const select = (
    <select value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="common">{t('Rápido (common, ~4.6k palavras)')}</option>
      <option value="big">{t('Completo (big, ~20k palavras — mais lento)')}</option>
      <option value="custom">{t('Personalizada')}</option>
    </select>
  )

  return (
    <>
      {showLabel ? (
        <label>
          {t('Wordlist do gobuster')}
          {select}
        </label>
      ) : (
        select
      )}

      {value === 'custom' && (
        <div className="custom-wordlist-picker">
          {disabledReason ? (
            <span className="muted">{disabledReason}</span>
          ) : (
            <>
              <select value={customWordlistId} onChange={(e) => onCustomWordlistIdChange(e.target.value)}>
                <option value="">{t('Selecione uma wordlist enviada')}</option>
                {wordlists.map((w) => (
                  <option key={w.wordlist_id} value={w.wordlist_id}>
                    {w.filename} ({w.line_count} {t('linhas')})
                  </option>
                ))}
              </select>
              {showUpload && (
                <>
                  <span className="muted">{t('ou envie uma nova:')}</span>
                  <input type="file" accept=".txt" onChange={(e) => onUploadFileChange(e.target.files[0] || null)} />
                  <button type="button" onClick={onUpload} disabled={!uploadFile || uploading}>
                    {uploading ? t('Enviando…') : t('Enviar')}
                  </button>
                </>
              )}
            </>
          )}
        </div>
      )}
    </>
  )
}
