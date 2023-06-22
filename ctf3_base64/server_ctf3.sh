#!/bin/bash

while true; do
    nc -l -p 4446 -c "./base64_ctf"
done
