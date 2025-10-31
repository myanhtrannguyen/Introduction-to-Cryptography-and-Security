Programming Assignment 2: AES Decryption

This project contains a Python script, decrypt.py, that decrypts ciphertexts encrypted with AES in both CBC and CTR modes.
1. How to Compile/Run
1.1 Environment
The script is written for Python 3.
1.2 Libraries Used
The program uses only standard Python libraries (binascii). It does not require any external libraries like pycryptodome, as a pure-Python implementation of AES is included directly in the script.
1.3 How to Run
To run the program, simply execute the Python script from your terminal:
python3 code.py
Or, if python is aliased to Python 3:
python code.py
The script will automatically run the decryption for all four questions and print the recovered plaintexts to the console.
2. How the Decryption Works
The program is split into three main parts:
A pure-Python implementation of the core AES-128 block cipher (the PureAES class).
Manual implementations of the decrypt_cbc and decrypt_ctr modes.
A main execution block that runs all problems.
General Decryption Steps
For every problem, the script performs these initial steps:
Hex Conversion: The hex-encoded key and full ciphertext string are converted into raw bytes using binascii.unhexlify().
IV Splitting: As per the assignment, the first 16 bytes of the full ciphertext are sliced off and stored as the Initialization Vector (IV).
Ciphertext Splitting: The remaining bytes after the IV are stored as the actual ciphertext to be decrypted.
AES-CBC Decryption Logic
Cipher Block Chaining (CBC) decryption is sequential. The decryption of one block depends on the ciphertext of the previous block.
The formula is: $P_i = \text{Decrypt}_K(C_i) \oplus C_{i-1}$
Block-by-Block: The script loops through the ciphertext in 16-byte blocks.
Previous Block: A variable holds the "previous" ciphertext block. For the very first block, this is initialized to the IV.
Decrypt: The PureAES.decrypt() function is called on the current ciphertext block ($C_i$).
XOR: The result of the decryption is XORed (^) with the previous ciphertext block ($C_{i-1}$) to get the plaintext block ($P_i$).
Update: The "previous" block variable is updated to be the current ciphertext block ($C_i$) for the next loop.
Unpadding (PKCS5): After all blocks are decrypted and joined, the unpad_pkcs5() function checks the final byte (let's call it N) and removes the last N bytes, first verifying that all of them have the value N.
AES-CTR Decryption Logic
Counter (CTR) mode turns the AES block cipher into a stream cipher. Decryption is the same as encryption.
The formula is: $P = C \oplus \text{Keystream}$, where $\text{Keystream} = \text{Encrypt}_K(\text{IV}) || \text{Encrypt}_K(\text{IV}+1) || \dots$
Counter Init: The 16-byte IV is treated as the starting value for a counter. It is converted from bytes to an integer.
Keystream Generation: The script enters a loop:
The current integer counter is converted back into 16 bytes.
The PureAES.encrypt() function (note: encrypt, not decrypt) is called on these counter bytes to create a 16-byte keystream block.
This keystream block is appended to a total keystream.
The integer counter is incremented (+ 1).
The loop repeats until the total keystream is at least as long as the ciphertext.
Truncate: The generated keystream is truncated to the exact length of the ciphertext.
XOR: The full ciphertext is XORed (^) with the full keystream to produce the final plaintext.
No Unpadding: CTR mode does not use padding, so the result is final.
3. All Recovered Plaintexts
Running the decrypt.py script produces the following plaintexts:
Question 1 (CBC): Basic CBC mode encryption needs padding.
Question 2 (CBC): Our implementation uses rand. IV
Question 3 (CTR): CTR mode lets you build a stream cipher from a block cipher.
Question 4 (CTR): Always avoid the two time pad!