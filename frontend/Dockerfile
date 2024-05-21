FROM node AS build

WORKDIR /client

COPY package.json yarn.lock ./
RUN yarn install

COPY . .

RUN yarn run build

FROM nginx:stable-alpine
COPY --from=build /client/dist /usr/share/nginx/html

CMD ["nginx", "-g", "daemon off;"]

EXPOSE 80