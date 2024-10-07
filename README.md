# CTF Buffer Overflow Challenges

This repository contains a collection of Capture the Flag (CTF) challenges focused on Buffer Overflow exploitation. The challenges are designed to teach various techniques for bypassing security mechanisms such as Position Independent Executables (PIE), Address Space Layout Randomization (ASLR), canaries, and the NX (No-eXecute) bit.

These challenges have been selected to add to the CTF that took place during the June 2023 National Cybersecurity Research Days ([JNIC 2023](https://2023.jnic.es/)). 

## Overview

These exercises aim to provide a hands-on experience in understanding memory exploitation and reverse engineering techniques. Each challenge requires you to identify and exploit buffer overflow vulnerabilities in different scenarios, ultimately allowing you to capture a hidden flag.

### Challenges

1. **[Exercise 1: Buffer Overflow to IP Info](#exercise-1-buffer-overflow-to-ip-info)**
   - **Difficulty**: Intermediate
   - **Disciplines**: Reverse Engineering, Exploiting
   - **Objective**: Exploit a buffer overflow in a binary to call a hidden function that reveals an API token.
   - **Security Mechanisms**: NX bit, ASLR, PIE
   - **Time Required**: ~50 minutes

2. **[Exercise 2: Buffer Overflow to Check DNI](#exercise-2-buffer-overflow-to-check-dni)**
   - **Difficulty**: Intermediate
   - **Disciplines**: Reverse Engineering, Exploiting, Steganography
   - **Objective**: Bypass a canary implementation to call a function that reveals a hidden image in Base64. The flag is embedded within the image.
   - **Security Mechanisms**: NX bit, Custom Canary
   - **Time Required**: ~120 minutes

3. **[Exercise 3: Buffer Overflow to Base64 Encoder](#exercise-3-buffer-overflow-to-base64-encoder)**
   - **Difficulty**: High
   - **Disciplines**: Reverse Engineering, Exploiting
   - **Objective**: Inject a shellcode to open a shell and read a file containing the flag. Involves advanced techniques like Return Oriented Programming (ROP).
   - **Security Mechanisms**: ASLR, with NX bit and PIE disabled
   - **Time Required**: ~120 minutes

### Full Documentation

For a comprehensive overview of the research, development, analysis, and resolution of these CTF challenges, we invite you to review the full documentation available in the Master's Thesis. This document provides an in-depth explanation of the methodologies used, the tools developed, and the findings derived throughout the project.

You can access the full Master's Thesis [here](TFM_DavidMohedanoVázquez.pdf).


## Getting Started

Each challenge includes:
- A binary file compiled with specific security measures.
- Source code (for local analysis and practice).
- A guide explaining the objective, necessary tools, and detailed steps to exploit the vulnerability.

### Prerequisites
- Basic knowledge of C programming, buffer overflows, and reverse engineering.
- Familiarity with tools like `Ghidra`, `Pwntools`, `checksec`, `ROPgadget`, `steghide`, and common Linux commands.

### Setting Up the Environment
1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/davidmohedanovazquez/CTF-buffer-overflow.git
   cd CTF-buffer-overflow
   ```
2. Ensure you have the necessary tools installed:
   - **Pwntools**: `pip install pwntools`
   - **Ghidra**: [Download from official site](https://ghidra-sre.org/)
   - **Steghide**: Install via package manager, e.g., `sudo apt-get install steghide`
   - **Checksec**: `sudo apt-get install checksec`
   - **ROPgadget**: `pip install ropgadget`

## Challenges Breakdown

### Exercise 1: Buffer Overflow to IP Info
This challenge focuses on bypassing the NX bit, ASLR, and PIE protections in a binary to call a function that reveals an API token. The primary objective is to manipulate the program's flow to execute a hidden function.

**Resources**:
- [More information](ctf1_ipinfo/)

### Exercise 2: Buffer Overflow to Check DNI
In this challenge, you will encounter a custom canary protection. The goal is to identify the vulnerability, bypass the canary, and extract the flag embedded in a Base64 encoded image. This includes a second part where you need to perform steganography.

**Resources**:
- [More information](ctf2_checkdni/)

### Exercise 3: Buffer Overflow to Base64 Encoder
This is the most advanced challenge, requiring you to identify and use Return Oriented Programming (ROP) gadgets to execute a shellcode. The final objective is to list the files in the directory and read the flag file.

**Resources**:
- [More information](ctf3_base64/)

## Contributing
If you would like to contribute additional challenges or improvements to the existing ones, feel free to open a pull request.

## License
This project is licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives License.

## Acknowledgments
- Developed as part of the Master's Thesis in Cybersecurity by David Mohedano Vázquez.
- Supervised by Lorena González Manzano.
