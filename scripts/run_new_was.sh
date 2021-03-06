#!/bin/bash
CURRENT_PORT=$(cat /home/ubuntu/service_url.inc | grep -Po '[0-9]+' | tail -1)
TARGET_PORT=0
PREV_PORT=0

echo "> Current port of running WAS is ${CURRENT_PORT}."
if [ ${CURRENT_PORT} -eq 3001 ]; then
  TARGET_PORT=3002
elif [ ${CURRENT_PORT} -eq 3002 ]; then
  TARGET_PORT=3001
else
  echo "> No WAS is connected to nginx"
fi

TARGET_PID=$(lsof -Fp -i TCP:${TARGET_PORT} | grep -Po 'p[0-9]+' | grep -Po '[0-9]+')

if [ ! -z ${TARGET_PID} ]; then
  echo "> Kill WAS running at ${TARGET_PORT}."
#  sudo kill ${TARGET_PID}
  sleep 5
fi

nohup java -jar -Dserver.port=${TARGET_PORT} /home/ubuntu/sharebnb/build/libs/* >/home/ubuntu/nohup.out 2>&1 &
echo "> Now new WAS runs at ${TARGET_PORT}."

exit 0