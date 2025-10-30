# README Report: RSA Decryption with CRT Optimization [cite: 2]

This report accompanies the source code submission for the "RSA Decryption with Chinese Remainder Theorem (CRT)" exercise.

---

## 1. Group Members [cite: 26]

* **Name:** Tran Nguyen My Anh, **Student ID:** 20235474
* **Name:** Nguyen Khanh Ly, **Student ID:** 20235600

---

## 2. Test Results [cite: 24]

The implementation was tested using both the small prime numbers from the worked example and the large prime numbers provided in the test data. Both functions (`rsa_decrypt` and `rsa_decrypt_crt`) produced identical, correct results in both test cases.

### Test 1: Small Primes (Worked Example)

* **Input:** $p=11$, $q=13$, $n=143$, $d=103$, $y=15$ 
* **Standard Decryption Result:** `141`
* **CRT Decryption Result:** `141`
* **Verification:** Both methods correctly match the expected result $x=141$ from the worked example.

### Test 2: Large Primes (Test Data)

* **Input:**
    * `p = 12345678901234567890123456869` 
    * `q = 98765432109876543210987654323` 
    * `d = 183037555140763297287823421841341095154128759392745892977` 
    * `y = 12345678901234567890` 
* **Standard Decryption Result:** `55060800662583164188075344335338116047702222384210620613`
* **CRT Decryption Result:** `55060800662583164188075344335338116047702222384210620613`
* **Verification:** Both `rsa_decrypt` and `rsa_decrypt_crt` produced the same decrypted plaintext.

---

## 3. Execution Time Comparison 

A comparison of execution times was performed using the large prime test data. The `timeit` module in Python was used to average the execution time over 100 iterations.

| Decryption Method | Average Execution Time (100 runs) |
| :--- | :--- |
| Standard (`rsa_decrypt`) | ~0.000107 seconds |
| CRT-Optimized (`rsa_decrypt_crt`) | ~0.000053 seconds |

### Analysis

The CRT-optimized version is **significantly faster** (approximately **2.01x** in this test).

This speedup confirms the purpose of using CRT for RSA decryption. The standard method computes one large exponentiation: $x = y^d \pmod n$, where $n$ is a large 2048-bit number (in real-world use). The CRT method replaces this single expensive operation with two smaller exponentiations: $x_p \equiv y_p^{d_p} \pmod p$ and $x_q \equiv y_q^{d_q} \pmod q$.

Because $p$ and $q$ are each about half the size of $n$, and the reduced exponents $d_p$ and $d_q$ are also smaller, these two computations are much faster than the single large one. This speed advantage heavily outweighs the small additional cost of transformation and recombination.