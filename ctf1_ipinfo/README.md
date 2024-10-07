# Exercise 1: Buffer Overflow to IP Info

## Overview
In this challenge, you will exploit a buffer overflow vulnerability in a binary that retrieves IP information using an API. The binary is protected by several security mechanisms, such as the NX bit, ASLR, and PIE, making this challenge an intermediate-level exercise in exploiting vulnerabilities.

## Objective
The primary goal of this exercise is to call a hidden function within the binary that prints an API token. You will bypass various security mechanisms to achieve this.

## How to serve the challenge

- To make this program work, you need to register on [ipinfo.io](https://ipinfo.io/signup), get an `API token` and add it to the `.env` file. This will need to be done twice:
   - Once to get the final API key that will be on the server,
   - And once to provide it to the user in the test `.env` file.
- The user will only be provided with the `ipinfo_ctf` binary, the `.env` file (with the API **test** key) binary and an instance to connect remotely to the server.
- Run `server_ctf1.sh`.

> [!WARNING]
> The solution to this challenge could potentially provide a way to execute commands remotely on the server. It is highly recommended to properly isolate the server to prevent unintended consequences or security risks. Use a sandboxed or isolated environment when running this challenge.


## Challenge Details

### Security Mechanisms
- **NX Bit**: Enabled to prevent certain areas of memory from being executed.
- **ASLR**: Randomizes the base addresses of the binary.
- **PIE (Position Independent Executables)**: Loads the binary at a different memory address on each execution.


### Steps to Solve

<details>
<summary>Show the steps</summary>

1. **Analyze the Binary**:
   - Use tools like `checksec` to identify the active security mechanisms:
     ```bash
     checksec --file=ipinfo_ctf
     ```
   - Run the binary to observe its behavior with different inputs.

2. **Identify Vulnerabilities**:
   - Locate the vulnerable function (`scanf` without proper input size limitation).
   - Disassemble the binary using reverse engineering tools like `Ghidra` or `IDA` to find the target function (`printEnvFile`) that you need to call.

3. **Exploit the Vulnerability**:
   - Find the offset needed to overwrite the return address using a cyclic pattern with `Pwntools`.
     ```python
     from pwn import *
     cyclic(100)  # Adjust the length as needed
     ```
   - Use the offset to inject the desired memory address into the return address.
   - Calculate the base address at runtime using the leaked memory address (due to PIE).

4. **Build the Exploit**:
   - Create a Python script using `Pwntools` to build and send the payload to the binary. 
   - Calculate the address of the target function (`printEnvFile`) at runtime, leveraging the leaked address and PIE offset.
   - Construct the final payload to inject into the binary and achieve the desired control flow redirection.

</details>


### Example Exploit Code

[Here's an example of the exploit script in Python](solve-ipinfo_ctf.py)


### Tools Used
- **Pwntools**: A powerful Python library used to craft the exploit.
- **Ghidra**: For reverse engineering and analyzing the binary.
- **checksec**: To verify the binary's security mechanisms.

## Expected Output
Upon successfully executing the exploit, the binary will print the API token, which serves as the flag for this challenge.

## Notes
- Make sure to explore the binary thoroughly to understand the active security measures.
- Experiment with different inputs to reveal the memory address leak.
- This exercise will give you a hands-on understanding of bypassing security mechanisms in binary exploitation.

## Resources
- [Binary](ipinfo_ctf)
- [Source Code](ipinfo_ctf.c)
- [Script to server the challenge](server_ctf1.sh)
- [Exploit to solve the challenge](solve-ipinfo_ctf.py)
- [Pwntools Documentation](https://docs.pwntools.com/)
- [Ghidra Official Site](https://ghidra-sre.org/)

## License
This challenge is part of a collection licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives License.

## Acknowledgments
- Developed as part of the Master's Thesis in Cybersecurity by David Mohedano Vázquez.
- Supervised by Lorena González Manzano.