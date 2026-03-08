FROM node:22-alpine
WORKDIR /app
RUN apk add --no-cache openssh-client bash wget
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build
ENV NODE_ENV=production
EXPOSE 8787
CMD ["node", "dist/index.js"]
