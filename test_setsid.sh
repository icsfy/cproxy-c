#!/bin/bash
setsid sleep 10 &
PID=$!
echo "PID: $PID"
ps -o pid,pgid,cmd -p $PID
kill -$PID
