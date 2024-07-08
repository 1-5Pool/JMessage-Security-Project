# JMessage: Secure Messaging System and Vulnerability Exploitation

## Overview

This project, developed as part of Practical Cryptographic Systems at Johns Hopkins University, implements JMessage, an end-to-end encrypted instant messaging system. The project consists of two main components:

1. A secure messaging client and server implementation
2. A demonstration of a padding oracle attack against the system

## Project Structure

- `jmessage_client.go`: The main client implementation
- `jmessage_server.py`: The server implementation (Python/Flask)

## Features

### Secure Messaging System

- End-to-end encryption using ECDH key exchange and ChaCha20 cipher
- Digital signatures using ECDSA
- User registration and authentication
- Public key distribution
- Message sending and receiving
- File attachment support

### Vulnerability Exploitation

- Implementation of a padding oracle attack
- Exploitation of CRC32 checksum linearity
- Incremental username registration technique for message decryption


## Attack Description

The implemented attack exploits a vulnerability in the JMessage system's handling of decryption errors and read receipts. It uses a padding oracle technique, combined with manipulation of the CRC32 checksum, to decrypt intercepted messages without knowledge of the recipient's private key.

Key aspects of the attack:
1. Modifies the sender's username in the ciphertext
2. Exploits the linearity property of CRC32 for checksum updates
3. Uses incremental username registration to shift the decryption "window"
4. Observes read receipt behavior to infer successful decryption

### Detailed Exploitation Process

1. **Ciphertext Modification**: 
   The attack starts by modifying the first byte of the sender's username in the ciphertext (e.g., changing 'charlie' to 'bharlie').

2. **CRC32 Checksum Manipulation**:
   The CRC32 checksum must be updated to match the modified ciphertext. This is where the linearity property of CRC32 is exploited.

   Let:
   - A be the original plaintext
   - B be the modification to the plaintext
   - C be a sequence of all zeros (0x00) of the same length as A

   The linearity property of CRC32 states that:
   
   CRC(A ⊕ B) = CRC(A) ⊕ CRC(B) ⊕ CRC(C)

   Where ⊕ represents the XOR operation.

   In our attack:
   - CRC(A) is the original checksum (last 4 bytes of the ciphertext)
   - CRC(B) is calculated for our modification
   - CRC(C) is pre-computed (as it's always the same for a given message length)

   The new checksum is calculated as: 
   
   New_Checksum = CRC(A) ⊕ CRC(B) ⊕ CRC(C)

3. **Incremental Username Registration**:
   To decrypt each byte of the message, we incrementally register new usernames (e.g., "mallory", "mallorya", "malloryaa", etc.). This shifts the position of the delimiter in the plaintext, allowing us to target different bytes of the message.

4. **Padding Oracle Exploitation**:
   For each byte:
   - We modify the ciphertext and update the checksum
   - Send the modified ciphertext to Alice
   - Observe whether a read receipt is received
   - If a read receipt is received, we've correctly guessed the byte
   - If not, we try the next possible byte value

5. **Message Reconstruction**:
   As we correctly guess each byte, we reconstruct the original plaintext message.

## Installation

1. Clone the repository:
  git clone https://github.com/1-5Pool/JMessage-Security-Project/

3. Install Go (for client and attack implementation):
[Go Installation Instructions](https://golang.org/doc/install)

4. Install Python and Flask (for server implementation):

## Usage

### Running the Server

python jmessage_server.py

### Running the Client

go run jmessage_client.go -username <username> -password <password>

### Performing the Attack

To perform the attack, follow these steps:

1. Register Alice and run it in headless mode:

go run jmessage_client.go -reg --headless

2. Register with Charlie and send a message:

go run jmessage_client.go -reg --username "charlie"

Then, send a message to Alice:

send alice
<Msg>

This creates a `cipher.txt` file in the current directory. Assuming the attacker has gotten hold of this ciphertext using MITM.

3. Use this file and run the command below:

go run jmessage_client.go -attack <file-location-cipher.txt> -victim alice -reg -username="charliea"



This process sets up the necessary accounts, generates an intercepted message, and then performs the padding oracle attack to decrypt the message.


## Ethical Considerations

This project is for educational purposes only. The vulnerabilities demonstrated should not be exploited in real-world systems without explicit permission. Always respect privacy and adhere to ethical guidelines in cybersecurity research and practice.


## Acknowledgements

- Matthew Green 
- Johns Hopkins University
