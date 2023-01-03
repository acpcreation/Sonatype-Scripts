#!/bin/bash

# How to run:
# sh setBaseURL.sh http://localhost:8070/ admin:admin123

url="${1}"
auth="${2}"

# auth="admin:admin123"

echo "Setting IQ BaseURL to: "$url
curl -u $auth -X PUT -H "Content-Type: application/json" -d '{"baseUrl": "'$url'", "forceBaseUrl": false}' ${url}api/v2/config

echo "IQ BaseURL set to: "
curl -u $auth "${url}api/v2/config?property=baseUrl"

