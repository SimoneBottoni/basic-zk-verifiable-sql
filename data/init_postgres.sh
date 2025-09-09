#!/bin/bash

POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres

docker run -d --name postgres_tpch \
  -p 5432:5432 \
  -e POSTGRES_USER=${POSTGRES_USER} \
  -e POSTGRES_PASSWORD=${POSTGRES_PASSWORD} \
  -e POSTGRES_DB=tpch \
  postgres

docker start postgres_tpch

sleep 10

docker cp . postgres_tpch:/data/
docker exec -u ${POSTGRES_USER} postgres_tpch psql tpch ${POSTGRES_USER} -f /data/schema.sql
