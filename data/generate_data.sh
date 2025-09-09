#!/bin/bash

DB_SIZE=1

docker pull scalytics/tpch
mkdir -p tpch_data

if [ -z "$(ls -A "$(pwd)/tpch_data")" ]; then
  docker run -it \
    --name tpch_data \
    -v "$(pwd)/tpch_data":/data scalytics/tpch:latest \
    ${DB_SIZE}

  docker stop tpch_data
  docker rm tpch_data
fi