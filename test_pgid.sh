#!/bin/bash
sudo sleep 10 &
PID=$!
ps -o pid,pgid,cmd -p $PID
kill -- -$PID
