# Exercise 3: Buffer Overflow to Base64 Encoder

## Overview
In this challenge, you will exploit a buffer overflow vulnerability in a binary that encodes a user-provided string to Base64. This binary is designed with certain security mechanisms disabled, allowing advanced exploitation techniques such as Return Oriented Programming (ROP) and shellcode injection.

## Objective
The primary objective is to gain control over the binary's execution flow using a ROP chain to inject a shellcode. This shellcode will open a shell on the target machine, allowing you to list files in the directory and extract the flag from a randomly named file.

## How to deploy

1. Create a fake flag and save it on a file with a random name.
2. Run `server_ctf3.sh`.

Before starting the challenge, the user will be provided with the following:
- An IP and a port that, when connected, will start running the `base64_ctf` program.
- A link to download a folder containing the compiled binary (`base64_ctf`), the file with the C code (`base64_ctf.c`) and a randomly named file containing a **fake** flag. Both the flag and the file name **must be different** from the one on the server.

> [!WARNING]
> The solution to this challenge will provide a way to execute commands remotely on the server. It is highly recommended to properly isolate the server to prevent unintended consequences or security risks. Use a sandboxed or isolated environment when running this challenge.


## Challenge Details

### Security Mechanisms
- **NX Bit**: Disabled, allowing the execution of injected shellcode.
- **ASLR**: Enabled to randomize memory addresses for stack and heap.
- **PIE (Position Independent Executables)**: Disabled, so the binary is loaded at a fixed address.


### Steps to Solve

<details>
<summary>Show the steps</summary>

1. **Analyze the Binary**:
   - Use `checksec` to verify the security mechanisms:
     ```bash
     checksec --file=base64_ctf
     ```
   - Run the binary with various inputs to understand its behavior. Identify the vulnerable input function (`scanf`).

2. **Identify Vulnerabilities**:
   - Disassemble the binary using reverse engineering tools such as `Ghidra` or `IDA`.
   - Locate the vulnerable function and find the ROP gadgets within the binary.

3. **Calculate the Offset**:
   - Use `Pwntools` to identify the offset needed to control the return address:
     ```python
     from pwn import *
     cyclic(100)  # Adjust the length as necessary
     ```

4. **Build the Exploit**:
   - **Find ROP Gadgets**:
     - Use a tool like `ROPgadget` to identify usable gadgets in the binary:
       ```bash
       ROPgadget --binary base64_ctf
       ```
     - Identify key gadgets that allow you to control the stack and registers, such as `mov eax, esp`, `add eax, ebp`, and `jmp eax`.

   - **Generate the Shellcode**:
     - Use `Pwntools` to generate a shellcode for a 32-bit Linux system that opens a shell:
       ```python
       shellcode = asm(shellcraft.i386.linux.sh())
       ```
   - **Construct the Payload**:
     - The payload will include:
       1. The initial padding to reach the return address.
       2. A ROP chain that sets up the stack for shellcode execution.
       3. An auxiliary space to safely execute the shellcode.
       4. The shellcode itself.

5. **Deploy the Exploit**:
   - Create a Python script using `Pwntools` to send the payload to the binary. Ensure that the script calculates addresses at runtime to bypass ASLR.
   - [Here's an example of the exploit script in Python](solve-base64.py)

6. **Interact with the Remote Shell**:
   - Once the script executes successfully, you should gain a shell on the target machine.
   - Use common Linux commands (`ls`, `cat`) to list files and read the flag's content.

</details>

### Example Exploit Code

[Here's an example of the exploit script in Python](solve-base64.py)

### Tools Used
- **Pwntools**: For crafting the exploit and generating the shellcode.
- **Ghidra**: To reverse engineer the binary and find ROP gadgets.
- **ROPgadget**: To locate usable ROP gadgets in the binary.
- **GDB**: For debugging and understanding the memory layout.

## Expected Output
Upon successfully exploiting the binary, you should gain a remote shell on the target machine. Using this shell, you can list the directory's contents and read the file containing the flag.

## Notes
- Understanding of ROP and shellcode injection is essential for this challenge.
- The exploit requires precise control over memory addresses and stack operations.
- Experiment with different gadgets and shellcodes if the initial attempt fails.

## Resources
- [Binary and Source Code](../binaries/exercise3)
- [Pwntools Documentation](https://docs.pwntools.com/)
- [Ghidra Official Site](https://ghidra-sre.org/)
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)

## Resources
- [Binary](base64_ctf)
- [Source Code](base64_ctf.c)
- [Script to server the challenge](server_ctf3.sh)
- [Exploit to solve the challenge](solve-base64.py)
- [File with a random name containing the flag](kj5g64gfy8943u509hg986409igh548)
- [Pwntools Documentation](https://docs.pwntools.com/)
- [Ghidra Official Site](https://ghidra-sre.org/)
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)

## License
This challenge is part of a collection licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives License.

## Acknowledgments
- Developed as part of the Master's Thesis in Cybersecurity by David Mohedano Vázquez.
- Supervised by Lorena González Manzano.