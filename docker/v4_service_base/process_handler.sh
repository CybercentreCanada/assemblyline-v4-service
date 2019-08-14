#!/usr/bin/env bash

# Start the first process
python3 -m alv4_service.run_service &
status=$?
if [ ${status} -ne 0 ]; then
  echo "Failed to start run_service: $status"
  exit ${status}
fi

# Start the second process
python3 -m al_service_client.task_handler &
status=$?
if [ ${status} -ne 0 ]; then
  echo "Failed to start task_handler: $status"
  exit ${status}
fi

# Naive check runs checks once a minute to see if either of the processes exited.
# This illustrates part of the heavy lifting you need to do if you want to run
# more than one service in a container. The container exits with an error
# if it detects that either of the processes has exited.
# Otherwise it loops forever, waking up every 10 seconds

while sleep 10; do
  ps aux |grep run_service |grep -q -v grep
  PROCESS_1_STATUS=$?
  ps aux |grep task_handler |grep -q -v grep
  PROCESS_2_STATUS=$?
  # If the greps above find anything, they exit with 0 status
  # If they are not both 0, then something is wrong
  if [ ${PROCESS_1_STATUS} -ne 0 ]; then
    echo "run_service process stopped"
    exit 1
  fi

  if [ ${PROCESS_2_STATUS} -ne 0 ]; then
    echo "task_handler process stopped"
    exit 1
  fi

done