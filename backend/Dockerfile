FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x /app/entrypoint.sh

EXPOSE 8000

# O serviço "worker" (docker-compose.yml) sobrescreve isso com
# entrypoint-worker.sh — esse ENTRYPOINT só vale pro serviço "backend".
ENTRYPOINT ["/app/entrypoint.sh"]
