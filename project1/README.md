# Programming Assignment 1: Many-Time Pad Attack

## Methodology

This project decrypts a target ciphertext that was encrypted using a one-time pad key reused across multiple messages. This scenario, known as a "many-time pad," is insecure due to the algebraic properties of the XOR operation.

My approach consists of a multi-stage attack:

1.  **Key Elimination via XOR:** The core principle is that XORing two ciphertexts ($C_1 = P_1 \oplus K$, $C_2 = P_2 \oplus K$) cancels out the shared key: $C_1 \oplus C_2 = P_1 \oplus P_2$. This allows analysis of the combined plaintexts without knowing the key.

2.  **Statistical Space Detection:** I exploited a property of ASCII encoding where XORing an alphabetic character with a space character (`0x20`) flips its case. My script systematically XORs the target ciphertext against all others. By counting how often the result is an alphabetic character at each position, it produces a statistical score, highlighting the most likely locations of spaces across the set of plaintexts.

3.  **Iterative Decryption and "Crib Dragging":**
    * Initially, I used an automated function to place spaces at high-scoring positions. This recovered the key bytes for those columns and revealed corresponding characters across all plaintexts.
    * These revealed characters served as a "crib" (a known plaintext fragment). By observing the partially decrypted messages, I could deduce words and characters in the target plaintext through context and logical guessing.
    * My script's interactive mode allowed me to manually set characters in the target message. Each correct guess revealed more of the key for that column, which in turn decrypted the corresponding character in all other messages, creating a chain reaction of discovery that led to the full decryption.