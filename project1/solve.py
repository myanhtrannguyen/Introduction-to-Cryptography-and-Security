# from Crypto.Util.strxor import strxor
import string

class ManyTimePadSolver:
    def __init__(self, ciphertexts, target):
        self.ciphertexts = [bytes.fromhex(ct) for ct in ciphertexts]
        self.target = bytes.fromhex(target)
        self.target_len = len(self.target)
        
        # Initialize recovered plaintexts
        self.recovered_target = [None] * self.target_len
        self.recovered_cts = [[None] * self.target_len for _ in ciphertexts]
        
    def xor_bytes(self, b1, b2):
        """XOR two byte sequences"""
        min_len = min(len(b1), len(b2))
        return bytes(a ^ b for a, b in zip(b1[:min_len], b2[:min_len]))
    
    def is_printable(self, byte):
        """Check if byte is likely printable ASCII"""
        return 32 <= byte <= 126
    
    def find_spaces_statistical(self):
        """Find likely space positions using statistical analysis"""
        scores = [0] * self.target_len
        
        for pos in range(self.target_len):
            for ct in self.ciphertexts:
                if pos >= len(ct):
                    continue
                    
                # XOR target with ciphertext at this position
                xor_val = self.target[pos] ^ ct[pos]
                
                # If target[pos] is space (0x20), xor_val should be in [A-Za-z]
                # If ct[pos] is space, xor_val should be in [A-Za-z]
                if (65 <= xor_val <= 90) or (97 <= xor_val <= 122):
                    scores[pos] += 1
        
        # High score = likely space in target or many ciphertexts
        return scores
    
    def attack_with_space(self, space_positions):
        """Use known space positions to decrypt"""
        for pos in space_positions:
            if pos >= self.target_len:
                continue
                
            # Assume target has space at this position
            key_byte = self.target[pos] ^ ord(' ')
            
            # Decrypt all ciphertexts at this position
            for i, ct in enumerate(self.ciphertexts):
                if pos < len(ct):
                    plain_byte = ct[pos] ^ key_byte
                    if self.is_printable(plain_byte):
                        self.recovered_cts[i][pos] = chr(plain_byte)
            
            # Decrypt target
            self.recovered_target[pos] = ' '
    
    def manual_decrypt(self, pos, target_char):
        """Manually set a character in target plaintext"""
        if pos >= self.target_len:
            return
            
        self.recovered_target[pos] = target_char
        key_byte = self.target[pos] ^ ord(target_char)
        
        # Update all ciphertexts
        for i, ct in enumerate(self.ciphertexts):
            if pos < len(ct):
                plain_byte = ct[pos] ^ key_byte
                if self.is_printable(plain_byte):
                    self.recovered_cts[i][pos] = chr(plain_byte)
    
    def guess_from_context(self, pos):
        """Try to guess character from context of other ciphertexts"""
        candidates = {}
        
        for ct_idx, ct in enumerate(self.ciphertexts):
            if pos >= len(ct):
                continue
            
            for test_char in string.ascii_letters + string.punctuation + ' ':
                key_byte = ct[pos] ^ ord(test_char)
                target_byte = self.target[pos] ^ key_byte
                
                if self.is_printable(target_byte):
                    target_char = chr(target_byte)
                    if target_char not in candidates:
                        candidates[target_char] = 0
                    candidates[target_char] += 1
        
        if candidates:
            # Return most common candidate
            return max(candidates, key=candidates.get)
        return None
    
    def auto_solve(self):
        """Automated solving with heuristics"""
        # Step 1: Find likely space positions
        print("[*] Analyzing space positions...")
        space_scores = self.find_spaces_statistical()
        threshold = max(space_scores) * 0.7  # Adjust threshold
        likely_spaces = [i for i, score in enumerate(space_scores) if score >= threshold]
        
        print(f"[*] Found {len(likely_spaces)} likely space positions")
        self.attack_with_space(likely_spaces)
        
        # Step 2: Try to fill remaining positions
        print("[*] Attempting to guess remaining characters...")
        for pos in range(self.target_len):
            if self.recovered_target[pos] is None:
                guess = self.guess_from_context(pos)
                if guess:
                    self.manual_decrypt(pos, guess)
        
        self.display_results()
    
    def display_results(self):
        """Display current decryption state"""
        print("\n" + "="*80)
        print("RECOVERED TARGET:")
        print("="*80)
        target_str = ''.join(c if c else '?' for c in self.recovered_target)
        print(target_str)
        print("="*80)
        
        print("\nOTHER PLAINTEXTS:")
        for i, pt in enumerate(self.recovered_cts):
            pt_str = ''.join(c if c else '?' for c in pt)
            print(f"CT{i}: {pt_str}")
    
    def interactive_mode(self):
        """Interactive manual decryption"""
        while True:
            self.display_results()
            print("\nOptions:")
            print("1. Auto-solve")
            print("2. Set character at position")
            print("3. Quit")
            
            choice = input("Choice: ").strip()
            
            if choice == '1':
                self.auto_solve()
            elif choice == '2':
                try:
                    pos = int(input("Position: "))
                    char = input("Character: ")
                    if len(char) == 1:
                        self.manual_decrypt(pos, char)
                except:
                    print("Invalid input")
            elif choice == '3':
                break


# Main execution
if __name__ == "__main__":
    ciphertexts = [
        '315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e',
        '234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f',
        '32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb',
        '32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa',
        '3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070',
        '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4',
        '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce',
        '315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3',
        '271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027',
        '466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83'
    ]
    
    target = '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904'
    
    solver = ManyTimePadSolver(ciphertexts, target)
    solver.interactive_mode()