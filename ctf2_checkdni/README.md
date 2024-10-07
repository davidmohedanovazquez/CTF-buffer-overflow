# Exercise 2: Buffer Overflow to Check DNI

## Overview
This challenge focuses on exploiting a buffer overflow vulnerability in a binary that validates a DNI (Documento Nacional de Identidad). The binary includes a custom canary mechanism to prevent the overflow, requiring a strategy to bypass it. The exercise also involves a second part: extracting a flag hidden within a Base64-encoded image using steganography.

## Objective
The goal of this challenge is to:
1. Bypass the custom canary protection to call a hidden function that prints a Base64-encoded image.
2. Decode the image and perform steganography to reveal the embedded flag.


## How to serve the challenge

1. Create a fake flag and embed it on the original image. An example of this with the files provided in `steghide_aux` folder would be:
```bash
$> steghide embed -cf jnic_original.jpg -ef flag.txt -sf jnic.jpg
```
2. Run `server_ctf2.sh`.

Before starting the challenge, the user will be provided with the following:
- An IP and a port that, when connected, starts running the `checkdni` program.
- A link to download a folder containing the compiled binary itself, a `canary.txt` file (with the **fake** canary) and a `jnic.jpg` image that has the **fake** flag embedded inside.

> [!WARNING]
> The solution to this challenge could potentially provide a way to execute commands remotely on the server. It is highly recommended to properly isolate the server to prevent unintended consequences or security risks. Use a sandboxed or isolated environment when running this challenge.

## Challenge Details

### Security Mechanisms
- **NX Bit**: Enabled to prevent code execution in certain memory areas.
- **Custom Canary**: A manually implemented stack canary to detect buffer overflows.
- **PIE (Position Independent Executables)**: Disabled to allow direct memory address access.


### Steps to Solve
<details>
<summary>Show the steps</summary>

1. **Analyze the Binary**:
   - Use `checksec` to identify security measures:
     ```bash
     checksec --file=checkdni_ctf
     ```
   - Run the binary with various inputs to understand its behavior and reveal any potential vulnerabilities.
   
2. **Identify Vulnerabilities**:
   - Disassemble the binary using `Ghidra` or `IDA` to find the target function (`image`) that reveals the Base64-encoded image.
   - Locate the custom canary implementation. Note the vulnerability: the canary is checked character by character, which can be exploited using a brute-force approach.

3. **Bypass the Canary**:
   - Develop a script to brute-force the canary character by character. Use the fact that the binary only checks each character one at a time to determine the correct value.
   - An example Python script for this brute-force process is in [`brute.sh`](brute.sh).

4. **Calculate the Offset**:
   - Use the cyclic pattern method from `Pwntools` to identify the offset needed to control the return address:
     ```python
     from pwn import *
     cyclic(100)  # Adjust the length as necessary
     ```

5. **Exploit the Vulnerability**:
   - Construct a payload that includes:
     - Nine filler characters (`'A' * 9`).
     - The discovered canary.
     - Filler bytes to reach the return address offset.
     - The address of the `image` function.
   - Send the payload using a Python script to call the `image` function and receive the Base64-encoded image.

6. **Decode the Image**:
   - Convert the Base64 output to an image using an online tool or command-line tools.
   - Use a steganography tool, such as `steghide`, to extract the flag from the image:
     ```bash
     steghide extract -sf image.jpg
     ```
   - Enter the canary value as the passphrase when prompted.

</details>

### Example Exploit Code

[Here's an example of the exploit script in Python](solve-checkdni.py)


### Tools Used
- **Pwntools**: To craft the exploit and brute-force the canary.
- **Ghidra**: For reverse engineering the binary.
- **Steghide**: To extract hidden data from the image.
- **Base64 Decoder**: For decoding the Base64-encoded image.

## Expected Output
Upon successfully exploiting the binary, you will receive a Base64-encoded image. Decoding the image and extracting the hidden data will reveal the flag.

## Notes
- Ensure you fully understand how the custom canary works and the implications of brute-forcing it.
- Use `steghide` with the brute-forced canary as the passphrase to extract the hidden data from the image.

## Resources
- [Binary](checkdni)
- [Source Code](checkdni_ctf.c)
- [File with the canary](canary.txt)
- [Image with the embed flag](jnic.jpg)
- [Script to server the challenge](server_ctf2.sh)
- [Exploit to solve the challenge](solve-checkdni.py)
- [Test resources to create a new image with embed flag](steghide_aux/)
- [Pwntools Documentation](https://docs.pwntools.com/)
- [Ghidra Official Site](https://ghidra-sre.org/)
- [Steghide](https://steghide.sourceforge.net/)

## License
This challenge is part of a collection licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives License.

## Acknowledgments
- Developed as part of the Master's Thesis in Cybersecurity by David Mohedano Vázquez.
- Supervised by Lorena González Manzano.