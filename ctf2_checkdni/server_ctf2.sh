#!/bin/bash

while true; do
    nc -lvp 4445 -c "./checkdni"
done
