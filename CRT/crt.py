import timeit

# --- Required Functions ---

def rsa_decrypt(y, d, n):
    """
    Performs standard RSA decryption by computing x = y^d mod n.
    
    Args:
        y (int): The ciphertext.
        d (int): The private exponent.
        n (int): The modulus (n = p*q).

    Returns:
        int: The decrypted plaintext x.
    """
    return pow(y, d, n)

def rsa_decrypt_crt(y, d, p, q):
    """
    Performs RSA decryption optimized with the Chinese Remainder Theorem (CRT).
    
    Args:
        y (int): The ciphertext.
        d (int): The private exponent.
        p (int): The first prime factor of n.
        q (int): The second prime factor of n.

    Returns:
        int: The decrypted plaintext x.
    """
    # Calculate n
    n = p * q

    # Step 1: Transformation to CRT Domain
    # y_p = y mod p
    # y_q = y mod q
    y_p = y % p
    y_q = y % q

    # Step 2: Exponentiation in CRT Domain
    # Reduce the private exponent
    # d_p = d mod (p-1)
    # d_q = d mod (q-1)
    d_p = d % (p - 1)
    d_q = d % (q - 1)

    # Compute the two smaller modular exponentiations
    # x_p = y_p^d_p mod p
    # x_q = y_q^d_q mod q
    x_p = pow(y_p, d_p, p)
    x_q = pow(y_q, d_q, q)

    # Step 3: Inverse Transformation (Recombination)
    # Compute coefficients c_p and c_q
    # c_p = q^-1 mod p
    # c_q = p^-1 mod q
    # We use pow(base, -1, modulus) for modular inverse (requires Python 3.8+)
    c_p = pow(q, -1, p)
    c_q = pow(p, -1, q)

    # Recombine to get the final result x
    # x = (q * c_p * x_p + p * c_q * x_q) mod n
    
    # We compute the terms modulo n to keep numbers manageable
    term1 = (q * c_p) % n
    term2 = (p * c_q) % n

    x = (term1 * x_p + term2 * x_q) % n
    
    return x

# --- Main execution for testing ---
if __name__ == "__main__":
    print("--- RSA Decryption with CRT Exercise ---")

    # --- Test 1: Small Primes (Worked Example) ---
    print("\n## Test 1: Small Primes (Worked Example)")
    p_small = 11
    q_small = 13
    n_small = p_small * q_small
    d_small = 103
    y_small = 15
    
    print(f"p = {p_small}, q = {q_small}, n = {n_small}, d = {d_small}, y = {y_small}")

    x_standard_small = rsa_decrypt(y_small, d_small, n_small)
    print(f"Standard Decryption Result: {x_standard_small}")

    x_crt_small = rsa_decrypt_crt(y_small, d_small, p_small, q_small)
    print(f"CRT Decryption Result:     {x_crt_small}")
    
    # Verify correctness from worked example
    assert x_standard_small == 141
    assert x_crt_small == 141
    print("Small Test Passed: Both methods match expected result (141).")


    # --- Test 2: Large Primes (Test Data) ---
    print("\n## Test 2: Large Primes (Test Data)")
    p_large = 12345678901234567890123456869
    q_large = 98765432109876543210987654323
    n_large = p_large * q_large
    d_large = 183037555140763297287823421841341095154128759392745892977
    y_large = 12345678901234567890

    print(f"p = {p_large}")
    print(f"q = {q_large}")
    print(f"y = {y_large}")

    print("\nCalculating (large primes)...")
    x_standard_large = rsa_decrypt(y_large, d_large, n_large)
    print(f"Standard Decryption Result: {x_standard_large}")

    x_crt_large = rsa_decrypt_crt(y_large, d_large, p_large, q_large)
    print(f"CRT Decryption Result:     {x_crt_large}")

    assert x_standard_large == x_crt_large
    print("Large Test Passed: Both methods produce the same result.")

    # --- Performance Comparison ---
    print("\n## Performance Comparison (Large Primes)")
    
    # Number of iterations for timeit
    iterations = 100 

    # Time standard decryption
    print(f"Timing standard decryption over {iterations} iterations...")
    standard_time = timeit.timeit(
        lambda: rsa_decrypt(y_large, d_large, n_large),
        number=iterations
    )
    avg_standard_time = standard_time / iterations

    # Time CRT decryption
    print(f"Timing CRT decryption over {iterations} iterations...")
    crt_time = timeit.timeit(
        lambda: rsa_decrypt_crt(y_large, d_large, p_large, q_large),
        number=iterations
    )
    avg_crt_time = crt_time / iterations

    print("\n--- Timing Results ---")
    print(f"Standard Decryption Avg Time: {avg_standard_time:.6f} seconds")
    print(f"CRT-Optimized Avg Time:     {avg_crt_time:.6f} seconds")

    if avg_crt_time < avg_standard_time:
        speedup = avg_standard_time / avg_crt_time
        print(f"Result: CRT is approximately {speedup:.2f}x faster.")
    else:
        print("Result: CRT was not faster in this test.")