# health_check.sh

# !/bin/bash

# Crawl current connected port of WAS
CURRENT_PORT=$(cat /home/ubuntu/service_url.inc | grep -Po '[0-9]+' | tail -1)
TARGET_PORT=0

# Toggle port Number
if [ ${CURRENT_PORT} -eq 3001 ]; then
  TARGET_PORT=3002
elif [ ${CURRENT_PORT} -eq 3002 ]; then
  TARGET_PORT=3001
else
  echo "> No WAS is connected to nginx"
  exit 1
fi


echo "> Start health check of WAS at 'http://127.0.0.1:${TARGET_PORT}' ..."
#CURRENT_PID=$(lsof -Fp -i TCP:${CURRENT_PORT} | grep -Po 'p[0-9]+' | grep -Po '[0-9]+')

for RETRY_COUNT in 1 2 3 4 5 6 7 8 9 10
do
  echo "> #${RETRY_COUNT} trying..."
  RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:${TARGET_PORT})

  if [ ${RESPONSE_CODE} -eq 200 ]; then
    echo "> New WAS successfully running"
    exit 0
#    if [ ! -z ${CURRENT_PID} ]; then
#      echo "> Kill WAS running at ${CURRENT_PORT}."
#      sudo kill ${CURRENT_PID}
#    fi
  elif [ ${RETRY_COUNT} -eq 10 ]; then
    echo "> Health check failed."
    exit 1
  fi
  sleep 10
done