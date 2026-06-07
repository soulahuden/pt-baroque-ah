FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
COPY honeypot.env .env
EXPOSE 3000
CMD ["node", "server.js"]
