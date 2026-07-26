// Um item por índice ("{cliente}-{suffix}") criado na Etapa 2. `tools` lista
// as ferramentas que gravam nesse índice — quando há mais de uma, o filtro
// "Origem" aparece na tela de achados.
export const TOOL_SUFFIXES = [
  { suffix: 'subdomains', label: 'Subdomínios', tools: ['assetfinder', 'subfinder', 'sublist3r', 'amass', 'dnsenum', 'dnsrecon'] },
  { suffix: 'httpx', label: 'Hosts vivos (HTTP)', tools: ['httprobe', 'httpx'] },
  { suffix: 'dns', label: 'DNS resolvido', tools: ['dnsx'] },
  { suffix: 'wayback', label: 'URLs históricas', tools: ['wayback', 'gau'] },
  { suffix: 'katana', label: 'Crawling (Katana)', tools: ['katana'] },
  { suffix: 'harvester', label: 'OSINT (theHarvester)', tools: ['theharvester'] },
  { suffix: 'rdap-domain', label: 'RDAP (domínio)', tools: ['rdap'] },
  { suffix: 'rdap-network', label: 'RDAP (bloco IP)', tools: ['rdap'] },
  { suffix: 'masscan', label: 'Masscan (portas)', tools: ['masscan'] },
  { suffix: 'nmap', label: 'Nmap (serviços)', tools: ['nmap'] },
  { suffix: 'nikto', label: 'Nikto (findings web)', tools: ['nikto'] },
  { suffix: 'nuclei', label: 'Nuclei (vulnerabilidades)', tools: ['nuclei'] },
  { suffix: 'dalfox', label: 'Dalfox (XSS)', tools: ['dalfox'] },
  { suffix: 'gobuster', label: 'Gobuster (diretórios)', tools: ['gobuster'] },
  { suffix: 'kiterunner', label: 'Kiterunner (rotas de API)', tools: ['kiterunner'] },
  { suffix: 'shodan', label: 'Shodan (dados passivos)', tools: ['shodan'] },
  { suffix: 'censys', label: 'Censys (dados passivos)', tools: ['censys'] },
  { suffix: 'wpscan', label: 'WPScan (WordPress)', tools: ['wpscan'] },
  { suffix: 'gowitness', label: 'Gowitness (screenshots)', tools: ['gowitness'] },
  { suffix: 'jobs', label: 'Execuções (jobs)', tools: [] },
  { suffix: 'wordlists', label: 'Wordlists customizadas', tools: [] },
]

export function suffixLabel(suffix) {
  return TOOL_SUFFIXES.find((t) => t.suffix === suffix)?.label ?? suffix
}

export function suffixTools(suffix) {
  return TOOL_SUFFIXES.find((t) => t.suffix === suffix)?.tools ?? []
}

// Nome da ferramenta como gravado em {cliente}-jobs (aba "Execuções") ->
// suffix de índice onde os achados dessa execução ficam. Não é o mesmo
// mapa de TOOL_SUFFIXES acima: rdap_domain/rdap_network são dois jobs
// distintos, mas o achado em si grava tool="rdap" nos dois casos (ver
// backend/parsers/rdap.py) — por isso os dois precisam de entrada própria
// aqui em vez de reaproveitar `tools` de TOOL_SUFFIXES.
const JOB_TOOL_SUFFIX = {
  assetfinder: 'subdomains',
  subfinder: 'subdomains',
  sublist3r: 'subdomains',
  amass: 'subdomains',
  dnsenum: 'subdomains',
  dnsrecon: 'subdomains',
  httpx: 'httpx',
  dnsx: 'dns',
  wayback: 'wayback',
  gau: 'wayback',
  katana: 'katana',
  theharvester: 'harvester',
  rdap_domain: 'rdap-domain',
  rdap_network: 'rdap-network',
  masscan: 'masscan',
  nmap: 'nmap',
  nikto: 'nikto',
  nuclei: 'nuclei',
  dalfox: 'dalfox',
  gobuster: 'gobuster',
  kiterunner: 'kiterunner',
  shodan: 'shodan',
  censys: 'censys',
  wpscan: 'wpscan',
  gowitness: 'gowitness',
}

export function suffixForJobTool(tool) {
  return JOB_TOOL_SUFFIX[tool]
}

export const COLUMNS = {
  subdomains: [
    { key: 'subdomain', label: 'Subdomínio' },
    { key: 'domain', label: 'Domínio' },
    { key: 'tool', label: 'Origem' },
    { key: '@timestamp', label: 'Quando' },
  ],
  httpx: [
    { key: 'url', label: 'URL' },
    { key: 'status_code', label: 'Status' },
    { key: 'alive', label: 'Vivo' },
    { key: 'tool', label: 'Origem' },
    { key: '@timestamp', label: 'Quando' },
  ],
  dns: [
    { key: 'subdomain', label: 'Subdomínio' },
    { key: 'ips', label: 'IPs' },
    { key: 'resolved', label: 'Resolveu' },
    { key: 'tool', label: 'Origem' },
    { key: '@timestamp', label: 'Quando' },
  ],
  wayback: [
    { key: 'url', label: 'URL' },
    { key: 'has_params', label: 'Com parâmetros' },
    { key: 'tool', label: 'Origem' },
    { key: '@timestamp', label: 'Quando' },
  ],
  katana: [
    { key: 'url', label: 'URL' },
    { key: 'domain', label: 'Domínio' },
    { key: '@timestamp', label: 'Quando' },
  ],
  harvester: [
    { key: 'type', label: 'Tipo' },
    { key: 'value', label: 'Valor' },
    { key: '@timestamp', label: 'Quando' },
  ],
  'rdap-domain': [
    { key: 'domain', label: 'Domínio' },
    { key: 'handle', label: 'Handle' },
    { key: 'registrant', label: 'Registrante', sortable: false },
    { key: 'nameservers', label: 'Nameservers' },
    { key: '@timestamp', label: 'Quando' },
  ],
  'rdap-network': [
    { key: 'handle', label: 'Handle' },
    { key: 'start_address', label: 'IP inicial' },
    { key: 'end_address', label: 'IP final' },
    { key: 'cidr', label: 'CIDR' },
    { key: 'country', label: 'País' },
    { key: 'org', label: 'Organização', sortable: false },
    { key: '@timestamp', label: 'Quando' },
  ],
  masscan: [
    { key: 'ip', label: 'IP' },
    { key: 'port', label: 'Porta' },
    { key: 'proto', label: 'Protocolo' },
    { key: 'state', label: 'Estado' },
    { key: '@timestamp', label: 'Quando' },
  ],
  nmap: [
    { key: 'ip', label: 'IP' },
    { key: 'hostname', label: 'Host' },
    { key: 'port', label: 'Porta' },
    { key: 'protocol', label: 'Protocolo' },
    { key: 'state', label: 'Estado' },
    { key: 'service', label: 'Serviço' },
    { key: 'product', label: 'Produto' },
    { key: 'version', label: 'Versão' },
    { key: '@timestamp', label: 'Quando' },
  ],
  nikto: [
    { key: 'host', label: 'Host' },
    { key: 'port', label: 'Porta' },
    { key: 'uri', label: 'URI' },
    { key: 'description', label: 'Descrição', sortable: false },
    { key: '@timestamp', label: 'Quando' },
  ],
  nuclei: [
    { key: 'severity', label: 'Severidade' },
    { key: 'template_id', label: 'Template' },
    { key: 'host', label: 'Host' },
    { key: 'matched_at', label: 'URL' },
    { key: 'cve', label: 'CVE' },
    { key: '@timestamp', label: 'Quando' },
  ],
  dalfox: [
    { key: 'severity', label: 'Severidade' },
    { key: 'type', label: 'Tipo' },
    { key: 'param', label: 'Parâmetro' },
    { key: 'url', label: 'URL' },
    { key: 'payload', label: 'Payload', sortable: false },
    { key: '@timestamp', label: 'Quando' },
  ],
  gobuster: [
    { key: 'url', label: 'URL' },
    { key: 'path', label: 'Caminho' },
    { key: 'status_code', label: 'Status' },
    { key: 'size', label: 'Tamanho' },
    { key: '@timestamp', label: 'Quando' },
  ],
  kiterunner: [
    { key: 'url', label: 'URL' },
    { key: 'path', label: 'Caminho' },
    { key: 'status_code', label: 'Status' },
    { key: 'size', label: 'Tamanho' },
    { key: '@timestamp', label: 'Quando' },
  ],
  shodan: [
    { key: 'ip', label: 'IP' },
    { key: 'port', label: 'Porta' },
    { key: 'product', label: 'Produto' },
    { key: 'version', label: 'Versão' },
    { key: 'org', label: 'Organização', sortable: false },
    { key: 'vulns', label: 'CVEs', sortable: false },
    { key: '@timestamp', label: 'Quando' },
  ],
  censys: [
    { key: 'ip', label: 'IP' },
    { key: 'port', label: 'Porta' },
    { key: 'protocol', label: 'Protocolo' },
    { key: 'software', label: 'Software', sortable: false },
    { key: 'org', label: 'Organização', sortable: false },
    { key: '@timestamp', label: 'Quando' },
  ],
  wpscan: [
    { key: 'finding_type', label: 'Tipo' },
    { key: 'component', label: 'Componente' },
    { key: 'component_version', label: 'Versão' },
    { key: 'title', label: 'Descrição', sortable: false },
    { key: 'fixed_in', label: 'Corrigido em' },
    { key: '@timestamp', label: 'Quando' },
  ],
  // Usado só pelo export CSV/JSON — a UI mostra gowitness como galeria
  // (ver ScreenshotGrid.jsx), não como DataTable.
  gowitness: [
    { key: 'url', label: 'URL' },
    { key: 'status_code', label: 'Status' },
    { key: 'title', label: 'Título', sortable: false },
    { key: 'technologies', label: 'Tecnologias', sortable: false },
    { key: '@timestamp', label: 'Quando' },
  ],
  jobs: [
    { key: 'tool', label: 'Ferramenta' },
    { key: 'target', label: 'Alvo' },
    { key: 'status', label: 'Status' },
    { key: 'scan_id', label: 'Scan' },
    { key: 'started_at', label: 'Quando' },
    { key: 'doc_count', label: 'Docs' },
    { key: 'error', label: 'Erro', sortable: false },
  ],
  wordlists: [
    { key: 'filename', label: 'Arquivo' },
    { key: 'line_count', label: 'Linhas' },
    { key: 'size_bytes', label: 'Tamanho (bytes)' },
    { key: '@timestamp', label: 'Quando' },
  ],
}

export function columnsFor(suffix) {
  return COLUMNS[suffix] ?? [{ key: 'tool', label: 'Ferramenta' }, { key: '@timestamp', label: 'Quando' }]
}
