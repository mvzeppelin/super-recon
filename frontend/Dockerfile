FROM node:22-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
# Template + hook do HTTPS opcional (ver README "HTTPS") — o hook decide em
# runtime se sobrescreve default.conf com o template, com base em
# HTTPS_ENABLED; sem a variável, a config HTTP acima (já copiada) continua
# valendo sem nenhuma mudança.
COPY nginx-https.conf.template /etc/nginx/nginx-https.conf.template
COPY docker-entrypoint.d/10-https.sh /docker-entrypoint.d/10-https.sh
RUN chmod +x /docker-entrypoint.d/10-https.sh
EXPOSE 80 443
