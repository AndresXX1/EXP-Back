FROM node:18-alpine

WORKDIR /app

COPY package.json ./

RUN npm install -g @nestjs/cli
RUN npm install

COPY . .

RUN npm run build

EXPOSE 9101

CMD ["npm", "run", "start:proddocker"]