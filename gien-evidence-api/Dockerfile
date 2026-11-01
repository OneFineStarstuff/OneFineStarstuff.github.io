FROM node:20-alpine

ENV NODE_ENV=production
ENV PORT=8080
WORKDIR /app

COPY package.json ./package.json
COPY src ./src

USER node
EXPOSE 8080
CMD ["npm", "start"]
