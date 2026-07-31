# Changelog

Mudanças notáveis deste projeto são documentadas aqui. Formato baseado em
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/), versionamento
em [SemVer](https://semver.org/lang/pt-BR/) (`MAJOR.MINOR.PATCH`).

## Como cortar uma versão

1. Adicione uma seção `## [X.Y.Z] - AAAA-MM-DD` no topo (logo abaixo desta
   seção), com as mudanças desde a última versão agrupadas em
   `Adicionado`/`Alterado`/`Corrigido`/`Removido`/`Segurança` — em
   linguagem humana (o que muda pra quem usa o projeto), não o log de
   commit cru.
2. Atualize `"version"` em `frontend/package.json` e `version=` do
   `FastAPI(...)` em `backend/app/main.py` para o mesmo número.
3. Commit essas mudanças, depois crie a tag e envie:
   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z   # tag não sobe sozinha com "git push"
   ```
4. Critério pra escolher o número: `PATCH` = correção sem mudar
   comportamento visível; `MINOR` = feature nova sem quebrar nada
   existente; `MAJOR` = mudança que quebra compatibilidade (ex: exige
   migração manual de dado, remove uma rota da API).

## [1.1.1] - 2026-07-31

### Segurança
- Validação de charset em `client`/`suffix` (rotas da API) contra
  injeção via wildcard/índice arbitrário do OpenSearch.
- Filtro de IP/CIDR privado, loopback, link-local e reservado aplicado
  de forma uniforme em todos os caminhos de disparo de scan (alvo
  submetido direto e IP resolvido de domínio) — evita SSRF contra a
  rede interna via alvo malicioso.
- Defesa adicional (redundante, no próprio módulo) contra path
  traversal na leitura/gravação de screenshots.
- Validação de formato de alvo (hostname/IP/CIDR) antes de repassar
  para as ferramentas de linha de comando.
- Sanitização de exportação CSV contra injeção de fórmula
  (Excel/Sheets) em valores vindos do alvo escaneado.
- Validação do destino de `NOTIFY_WEBHOOK_URL` (ao salvar e a cada
  disparo) contra SSRF/DNS rebinding.
- Parsers de XML (nmap, nikto) trocados para `defusedxml`, contra
  negação de serviço por expansão de entidade.

## [1.1.0] - 2026-07-26

### Adicionado
- Suporte a HTTPS, desligado por padrão. Ligado (`HTTPS_ENABLED` no
  `.env`): frontend redireciona automaticamente HTTP → HTTPS; backend
  passa a responder só em HTTPS (API consumida por script, sem redirect).
  Certificado lido de `certs/fullchain.pem`/`certs/privkey.pem` — script
  `certs/generate-self-signed-cert.sh` gera um autoassinado pra dev/teste;
  ver README "HTTPS" pra instalar um de verdade (Let's Encrypt ou outra CA).

## [1.0.0] - 2026-07-26

Primeira versão marcada como estável.

### Adicionado
- Pipeline de recon em 4 fases (passivo, resolução de domínio/IP,
  portas/serviços, Fase 4 ativa em toda URL viva), orquestrado via Celery,
  cada ferramenta rodando em container Kali efêmero.
- Dashboard React: clientes, histórico de scans, achados por ferramenta
  com filtros/paginação persistidos na URL, comparação entre scans,
  detalhe de ativo, relatório executivo (score de risco agregado) e
  gráficos.
- Enriquecimento passivo via Shodan e Censys; WPScan, Gowitness
  (screenshots), Dalfox (XSS) e Kiterunner (rotas de API) na Fase 4 (os
  três últimos opt-in, com checklist por execução).
- Wordlists customizadas do gobuster (upload por cliente).
- Recorrência de scans (alvos salvos com agendamento diário/semanal/
  mensal) e monitor de saúde da plataforma.
- Notificação em achado crítico (Slack e/ou webhook genérico).
- Sistema de autenticação com usuários/papéis (admin/operator/viewer),
  sessão via token bearer, e log de auditoria das ações que mudam dado.
- Tela de Configurações: dezenas de opções (timeouts por ferramenta,
  notificação, integrações externas, limites de upload etc.) editáveis
  em runtime, sem editar `.env` nem reiniciar.
- Retenção de dados via ILM/ISM do OpenSearch, scripts de backup/restore.
- Interface em português e inglês.

### Segurança
- Rate limiting/lockout de login por username, verificação de senha com
  timing constante (evita enumerar usuário por tempo de resposta),
  redação de token de sessão nos logs de acesso, invalidação de sessões
  ao trocar senha.
