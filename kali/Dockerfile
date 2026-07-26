FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:${PATH}"

# Ferramentas disponíveis via apt nos repositórios do Kali
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        masscan \
        nikto \
        gobuster \
        dirb \
        sublist3r \
        dnsenum \
        dnsrecon \
        theharvester \
        wpscan \
        chromium \
        # ^ único uso: gowitness (screenshot de página via Chrome DevTools
        # Protocol) — não é usado por nenhuma outra ferramenta. Sozinho
        # adiciona ~300MB à imagem; roda condicionado a GOWITNESS_ENABLED.
        golang-go \
        git \
        ca-certificates \
        curl \
        jq \
        whois \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Ferramentas Go (tomnomnom + projectdiscovery + openrdap + owasp-amass)
RUN go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/httprobe@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/openrdap/rdap/cmd/rdap@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest && \
    go install -v github.com/sensepost/gowitness@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/assetnote/kiterunner/cmd/kiterunner@latest && \
    rm -rf /root/.cache/go-build

# Pré-baixa os templates do nuclei no build, para não depender de rede em cada
# execução efêmera do container.
RUN nuclei -ut -silent || true

# Mesma lógica acima para o modelo de classificação de página do httpx
# (detecção de página de erro/login/captcha via ML) — sem isso, cada
# container efêmero baixaria ~93MB do Hugging Face na primeira chamada,
# visto na prática ao rodar httpx contra um alvo qualquer (adiciona uns bons
# segundos + banda em todo scan, não só no primeiro).
RUN httpx -u https://example.com -json -silent || true

# Mesma lógica acima, para a base de dados de vulnerabilidades (WPVulnDB) do
# wpscan — sem isso, a primeira execução de cada container efêmero baixaria a
# base do zero (visto na prática: ~6KB de metadados + arquivos de
# fingerprint), gastando rede e tempo à toa em todo scan.
RUN wpscan --update || true

# Pré-baixa a wordlist do kiterunner (apiroutes-260227, ~364k linhas/10.7MB)
# no build, mesma lógica acima: sem isso, cada container efêmero baixaria o
# arquivo do zero na primeira execução. O truncamento por N linhas
# (KITERUNNER_WORDLIST_LINES) acontece em tempo de scan via "-A nome:N",
# lendo do mesmo arquivo em cache — baixar o arquivo completo uma vez no
# build cobre qualquer N configurado depois, sem depender de rede em nenhum
# scan futuro.
RUN kiterunner wordlist save apiroutes-260227 || true

WORKDIR /data

# Sem ENTRYPOINT: o orquestrador chama "docker run --rm kali-tools:1.0 <ferramenta> <args>"
# passando a ferramenta diretamente como comando (ex: "assetfinder -subs-only <domínio>").
