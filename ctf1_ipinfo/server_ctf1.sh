#!/bin/bash

while true; do
    nc -l -p 4444 -c "./ipinfo_ctf"
done
