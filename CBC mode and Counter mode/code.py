import binascii
class PureAES:
    # S-box (Substitution Box)
    s_box = (
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )

    # Inverse S-box
    inv_s_box = (
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    )

    # Round Constant
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
        0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    )

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes (AES-128)")
        self.block_size = 16
        self._key_schedule = self._expand_key(key)

    def _expand_key(self, key: bytes) -> list[list[int]]:
        key_schedule = [list(key)]
        
        for i in range(10): # 10 rounds for 128-bit key
            prev_key = key_schedule[-1]
            new_key = [0] * 16
            
            temp = [prev_key[13], prev_key[14], prev_key[15], prev_key[12]]
            
            for j in range(4):
                temp[j] = self.s_box[temp[j]]
                
            # XOR with Rcon
            temp[0] ^= self.r_con[i + 1]
            
            # XOR with the first word of the previous key
            for j in range(4):
                new_key[j] = prev_key[j] ^ temp[j]
            # Generate remaining words
            for j in range(4, 16):
                new_key[j] = prev_key[j] ^ new_key[j - 4]
                
            key_schedule.append(new_key)
            
        return key_schedule

    def _add_round_key(self, state: list[list[int]], round_key: list[int]):
        for r in range(4):
            for c in range(4):
                state[r][c] ^= round_key[r + c * 4]

    def _sub_bytes(self, state: list[list[int]], inverse: bool = False):
        box = self.inv_s_box if inverse else self.s_box
        for r in range(4):
            for c in range(4):
                state[r][c] = box[state[r][c]]

    def _shift_rows(self, state: list[list[int]], inverse: bool = False):
        for r in range(1, 4):
            row = state[r]
            if inverse:
                # Shift right by r
                state[r] = row[-r:] + row[:-r]
            else:
                # Shift left by r
                state[r] = row[r:] + row[:r]

    def _xtime(self, a: int) -> int:
        return ((a << 1) ^ 0x1b if (a & 0x80) else (a << 1)) & 0xff

    def _gmul(self, a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b 
            a &= 0xff
            b >>= 1
        return p

    def _mix_columns(self, state: list[list[int]], inverse: bool = False):
        for c in range(4):
            col = [state[r][c] for r in range(4)]
            if inverse:
                # Inverse mix columns matrix multiplication
                state[0][c] = self._gmul(col[0], 0x0e) ^ self._gmul(col[1], 0x0b) ^ self._gmul(col[2], 0x0d) ^ self._gmul(col[3], 0x09)
                state[1][c] = self._gmul(col[0], 0x09) ^ self._gmul(col[1], 0x0e) ^ self._gmul(col[2], 0x0b) ^ self._gmul(col[3], 0x0d)
                state[2][c] = self._gmul(col[0], 0x0d) ^ self._gmul(col[1], 0x09) ^ self._gmul(col[2], 0x0e) ^ self._gmul(col[3], 0x0b)
                state[3][c] = self._gmul(col[0], 0x0b) ^ self._gmul(col[1], 0x0d) ^ self._gmul(col[2], 0x09) ^ self._gmul(col[3], 0x0e)
            else:
                # Standard mix columns matrix multiplication
                state[0][c] = self._gmul(col[0], 2) ^ self._gmul(col[1], 3) ^ col[2] ^ col[3]
                state[1][c] = col[0] ^ self._gmul(col[1], 2) ^ self._gmul(col[2], 3) ^ col[3]
                state[2][c] = col[0] ^ col[1] ^ self._gmul(col[2], 2) ^ self._gmul(col[3], 3)
                state[3][c] = self._gmul(col[0], 3) ^ col[1] ^ col[2] ^ self._gmul(col[3], 2)

    def _bytes_to_state(self, data: bytes) -> list[list[int]]:
        state = [[0] * 4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                state[r][c] = data[r + c * 4]
        return state

    def _state_to_bytes(self, state: list[list[int]]) -> bytes:
        return bytes(state[r][c] for c in range(4) for r in range(4))

    def encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) != 16:
            raise ValueError("Plaintext block must be 16 bytes")
        
        state = self._bytes_to_state(plaintext)
        self._add_round_key(state, self._key_schedule[0])

        for i in range(1, 10):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self._key_schedule[i])

        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self._key_schedule[10])
        
        return self._state_to_bytes(state)

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != 16:
            raise ValueError("Ciphertext block must be 16 bytes")
            
        state = self._bytes_to_state(ciphertext)
        self._add_round_key(state, self._key_schedule[10])

        for i in range(9, 0, -1):
            self._shift_rows(state, inverse=True)
            self._sub_bytes(state, inverse=True)
            self._add_round_key(state, self._key_schedule[i])
            self._mix_columns(state, inverse=True)

        self._shift_rows(state, inverse=True)
        self._sub_bytes(state, inverse=True)
        self._add_round_key(state, self._key_schedule[0])
        
        return self._state_to_bytes(state)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def unpad_pkcs5(data: bytes) -> bytes:
    if not data:
        return b'' 

    padding_length = data[-1]
    if padding_length == 0 or padding_length > len(data):
        print(f"Warning: Invalid padding length detected ({padding_length}). Returning data as-is.")
        return data
    padding_bytes = data[-padding_length:]
    expected_padding = bytes([padding_length]) * padding_length
    
    if padding_bytes != expected_padding:
        print("Warning: Invalid padding bytes. Data may be corrupt. Returning data as-is.")
        return data
    return data[:-padding_length]

def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    block_size = 16 # Use our internal class's block size
    if len(ciphertext) % block_size != 0:
        raise ValueError("Ciphertext length must be a multiple of the block size")

    cipher = PureAES(key)
    
    plaintext = b'' 

    previous_ciphertext_block = iv

    for i in range(0, len(ciphertext), block_size):
        current_ciphertext_block = ciphertext[i : i + block_size]
        
        # Step 1: Decrypt the current block (Decrypt(K, C_i))
        decrypted_block = cipher.decrypt(current_ciphertext_block)
        
        # Step 2: XOR the result with the *previous ciphertext block* (XOR C_{i-1})
        plaintext_block = xor_bytes(decrypted_block, previous_ciphertext_block)
        
        # Step 3: Append this plaintext block to our result
        plaintext += plaintext_block
        
        # Step 4: For the *next* loop, the "previous" block will be the *current* ciphertext block.
        previous_ciphertext_block = current_ciphertext_block
        
    # After decrypting all blocks, we must remove the padding.
    return unpad_pkcs5(plaintext)

def decrypt_ctr(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = PureAES(key)
    
    keystream = b''
    counter_as_integer = int.from_bytes(iv, 'big')
    
    while len(keystream) < len(ciphertext):
        try:
            counter_as_bytes = counter_as_integer.to_bytes(16, 'big')
        except OverflowError:
            print("Error: Counter overflow during CTR keystream generation.")
            break

        keystream_block = cipher.encrypt(counter_as_bytes)
        keystream += keystream_block
        counter_as_integer += 1
    keystream = keystream[:len(ciphertext)]
    plaintext = xor_bytes(ciphertext, keystream)
    return plaintext

def solve(q_num, mode, key_hex, ct_hex):
    print(f"--- Question {q_num} ({mode.upper()}) ---")
    
    try:
        # 1. Convert hex strings to raw bytes
        key = binascii.unhexlify(key_hex)
        full_ciphertext = binascii.unhexlify(ct_hex)
        
        # 2. Split the full ciphertext into the IV and the actual ciphertext
        iv = full_ciphertext[:16]
        # The rest of the string is the ciphertext we need to decrypt
        ciphertext = full_ciphertext[16:]
        
        # Print the inputs for clarity
        print(f"Key (hex): {key_hex}")
        print(f"IV (hex):  {binascii.hexlify(iv).decode()}")
        print(f"Ciphertext (hex):  {binascii.hexlify(ciphertext).decode()}")

        plaintext_bytes = b''
        
        # 3. Call the correct decryption function based on the 'mode'
        if mode == 'cbc':
            plaintext_bytes = decrypt_cbc(key, iv, ciphertext)
        elif mode == 'ctr':
            plaintext_bytes = decrypt_ctr(key, iv, ciphertext)
        
        # 4. Try to decode the resulting bytes into a human-readable string (Most plaintexts are UTF-8)
        try:
            plaintext_str = plaintext_bytes.decode('utf-8')
            print(f"==> Recovered Plaintext: {plaintext_str}")
        except UnicodeDecodeError:
            # If it's not valid UTF-8, just print the raw bytes/hex
            print(f"==> Recovered Plaintext (raw): {plaintext_bytes}")
            print(f"==> Recovered Plaintext (hex): {binascii.hexlify(plaintext_bytes).decode()}")
            
    except Exception as e:
        print(f"An error occurred while solving: {e}")
    
    # Add a newline for cleaner output
    print("-" * (27 + len(str(q_num))) + "\n")
if __name__ == "__main__":
    # Question 1: CBC
    CBC_KEY_1 = "140b41b22a29beb4061bda66b6747e14"
    CBC_CT_1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"

    # Question 2: CBC
    CBC_KEY_2 = "140b41b22a29beb4061bda66b6747e14"
    CBC_CT_2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

    # Question 3: CTR
    CTR_KEY_1 = "36f18357be4dbd77f050515c73fcf9f2"
    CTR_CT_1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"

    # Question 4: CTR
    CTR_KEY_2 = "36f18357be4dbd77f050515c73fcf9f2"
    CTR_CT_2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    
    solve(1, 'cbc', CBC_KEY_1, CBC_CT_1)
    solve(2, 'cbc', CBC_KEY_2, CBC_CT_2)
    solve(3, 'ctr', CTR_KEY_1, CTR_CT_1)
    solve(4, 'ctr', CTR_KEY_2, CTR_CT_2)