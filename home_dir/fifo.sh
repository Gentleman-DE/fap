#!/usr/bin/nice /bin/bash
#mkfifo /home/pi/ips
fifo_name="/home/fap/ips"
while true
do
    sleep 0.5
    if read line; then
            /home/fap/importIP2FW.sh $line
    fi
done <"$fifo_name"
