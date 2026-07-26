import { Link } from 'react-router-dom'
import { suffixForJobTool, suffixTools } from '../toolSchemas.js'

// Nº de docs de uma execução concluída (aba "Execuções") vira link direto
// pra tabela de achados que ela gerou, já filtrada pro scan/ferramenta/alvo
// dessa execução específica — sem isso, achar exatamente esses docs exige
// abrir a tabela certa e montar os filtros na mão. `target` sempre vira
// campo "target" no doc (ver backend/parsers/common.py::base_doc), por
// isso funciona como busca livre (`q`) pra restringir a essa execução.
export default function JobDocsLink({ client, row }) {
  const suffix = suffixForJobTool(row.tool)
  if (!suffix || !row.doc_count || row.status !== 'ok') return row.doc_count

  const params = new URLSearchParams({ scan_id: row.scan_id })
  // Só filtra por ferramenta quando o suffix tem mais de uma (ex:
  // subdomains) — pulado de propósito pro caso rdap_domain/rdap_network
  // (o doc grava tool="rdap", não bateria com o nome do job).
  if (suffixTools(suffix).includes(row.tool)) params.set('tool', row.tool)
  if (row.target) params.set('q', row.target)

  return (
    <Link to={`/clients/${encodeURIComponent(client)}/${suffix}?${params.toString()}`} onClick={(e) => e.stopPropagation()}>
      {row.doc_count}
    </Link>
  )
}
