#!/bin/bash

while true
do
    echo "$(date +'%H:%M:%S.%3N') - Running Attack !!!!!!!!!Spectre!!!!!!!!!!" >> GT.txt
    # kill -SIGUSR1 $(pidof spectre.out)
    kill -SIGUSR1 $(pidof spectre_v1_pht_sa)
    sleep_time1=$((5 + RANDOM % 15))
    sleep $sleep_time1
    echo "$(date +'%H:%M:%S.%3N') - Stopping Attack !!!!!!!!!Spectre!!!!!!!!!!" >> GT.txt
    # kill -SIGUSR2 $(pidof spectre.out)
    kill -SIGUSR2 $(pidof spectre_v1_pht_sa)
    sleep_time2=$((5 + RANDOM % 15))
    sleep $sleep_time2
done