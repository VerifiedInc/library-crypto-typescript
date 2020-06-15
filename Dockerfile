FROM node:12-alpine

WORKDIR /app

COPY package.json /app/
COPY yarn.lock /app/

RUN yarn install

COPY ./ /app/

RUN yarn build
