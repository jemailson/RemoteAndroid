FROM node:20-alpine
WORKDIR /app
COPY server/package*.json ./
RUN npm ci --production
COPY server/ ./
COPY web/ ./web/
EXPOSE 3000
ENV PORT=3000
ENV ADMIN_PASS=remoteandroid2026
CMD ["node", "server.js"]
