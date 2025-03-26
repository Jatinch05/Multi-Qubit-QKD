import hashlib
from qiskit_aer import AerSimulator
from alice import alice_generate_qubits
from bob import bob_measure_circuit
from cpabe import policy_example
from Crypto.Cipher import AES

def derive_aes_key_from_measurements(measured_results):
    """
    Derive a 128-bit AES key from the measurement outcomes.
    Concatenate the bit strings from each measurement, hash them using SHA‑256,
    and use the first 16 bytes of the digest as the AES key.
    """
    combined = ''.join(list(result.keys())[0] for result in measured_results)
    hash_digest = hashlib.sha256(combined.encode()).digest()
    return hash_digest[:16]

def encrypt_message_aes(key, plaintext):
    """
    Encrypt the plaintext using AES in EAX mode.
    Returns a tuple: (nonce, ciphertext, tag).
    """
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce, ciphertext, tag

def decrypt_message_aes(key, nonce, ciphertext, tag):
    """
    Decrypt the AES ciphertext using the given key, nonce, and tag.
    Returns the decrypted plaintext.
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode()

def main():
    num_pairs = 8
    circuits, chaotic_angles = alice_generate_qubits(num_pairs)
    print("Generated chaotic angles:", chaotic_angles)
    
    simulator = AerSimulator()
    measured_results = []
    for qc in circuits:
        qc = bob_measure_circuit(qc)
        job = simulator.run(qc, shots=1)
        result = job.result().get_counts(qc)
        measured_results.append(result)
    print("Measured circuit results:")
    for idx, res in enumerate(measured_results):
        print(f"  Circuit {idx}: {res}")
    
    aes_key = derive_aes_key_from_measurements(measured_results)
    print("Derived AES key (hex):", aes_key.hex())

    original_message = f"Secret cloud data protected by measurement-derived key: {aes_key.hex()}"
    print("Original Message:", original_message)
    
    nonce, ciphertext, tag = encrypt_message_aes(aes_key, original_message)
    print("\n[AES] Encrypted Message (hex):", ciphertext.hex())
    
 
    user_attributes_valid = {"Manager", "Finance", "HR"}
    print("\n[CP-ABE] Checking valid attributes:")
    if policy_example(user_attributes_valid):
        try:
            decrypted_message = decrypt_message_aes(aes_key, nonce, ciphertext, tag)
            print("Decryption succeeded with valid attributes:")
            print(decrypted_message)
        except Exception as e:
            print("AES Decryption failed with valid attributes:", e)
    else:
        print("Access denied: User attributes do not satisfy the CP-ABE policy.")
 
    user_attributes_invalid = {"Employee", "Sales"}
    print("\n[CP-ABE] Checking invalid attributes:")
    if policy_example(user_attributes_invalid):
        try:
            decrypted_message_invalid = decrypt_message_aes(aes_key, nonce, ciphertext, tag)
            print("Decryption unexpectedly succeeded with invalid attributes:")
            print(decrypted_message_invalid)
        except Exception as e:
            print("AES Decryption failed with invalid attributes:", e)
    else:
        print("Access denied: User attributes do not satisfy the CP-ABE policy.")

if __name__ == "__main__":
    main()

"""Conclusion
This simulation demonstrates a simplified workflow:
- Simulated QKD Key Generation:  
  Through entangled qubit pairs with chaotic rotations.
- AES Encryption:  
  Using a key derived from quantum measurements.
- CP-ABE Simulation:  
  Enforcing attribute-based access control.
Though simplified, this proof-of-concept captures the core ideas of integrating QKD with CP-ABE for cloud data security. It provides a foundation for further development towards a fully robust cryptographic system."""