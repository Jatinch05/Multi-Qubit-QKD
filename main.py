# main.py

import hashlib
import random
import boto3
import os
from qiskit_aer import AerSimulator
from alice import alice_generate_qubits
from bob import bob_measure_circuit
from cpabe import policy_example
from Crypto.Cipher import AES

# AWS S3 configuration (update with your bucket name and region)
# AWS S3 configuration (update with your bucket name and region)
S3_BUCKET = '2022bcy0040bucket'  # Use your bucket's name
S3_REGION = 'eu-north-1'          # Use your bucket's AWS region (Europe (Stockholm))
ENCRYPTED_DATA_FILENAME = 'encrypted_data.bin'

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

def upload_to_s3(filename, bucket, object_name):
    """
    Upload a file to an S3 bucket.
    """
    s3 = boto3.client('s3', region_name=S3_REGION)
    s3.upload_file(filename, bucket, object_name)
    print(f"Uploaded {filename} to s3://{bucket}/{object_name}")

def download_from_s3(bucket, object_name, filename):
    """
    Download a file from an S3 bucket.
    """
    s3 = boto3.client('s3', region_name=S3_REGION)
    s3.download_file(bucket, object_name, filename)
    print(f"Downloaded s3://{bucket}/{object_name} to {filename}")

def main():
    # === QKD Simulation ===
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
    
    # Derive AES key from measurement outcomes
    aes_key = derive_aes_key_from_measurements(measured_results)
    print("Derived AES key (hex):", aes_key.hex())
    
    # === AES Encryption (Local) ===
    original_message = f"Secret cloud data secured with measurement-derived key: {aes_key.hex()}"
    print("Original Message:", original_message)
    
    nonce, ciphertext, tag = encrypt_message_aes(aes_key, original_message)
    print("\n[AES] Encrypted Message (hex):", ciphertext.hex())
    
    # Save the encrypted data (nonce, ciphertext, tag) to a local file.
    with open(ENCRYPTED_DATA_FILENAME, 'wb') as f:
        # Save nonce, tag lengths and then the data itself.
        f.write(len(nonce).to_bytes(1, 'big'))
        f.write(nonce)
        f.write(len(tag).to_bytes(1, 'big'))
        f.write(tag)
        f.write(ciphertext)
    print(f"Encrypted data saved to {ENCRYPTED_DATA_FILENAME}")
    
    # === Cloud Upload ===
    upload_to_s3(ENCRYPTED_DATA_FILENAME, S3_BUCKET, ENCRYPTED_DATA_FILENAME)
    
    # === Cloud Download ===
    # Simulate a decryption request: download the encrypted file from S3.
    download_filename = "downloaded_" + ENCRYPTED_DATA_FILENAME
    download_from_s3(S3_BUCKET, ENCRYPTED_DATA_FILENAME, download_filename)
    
    # Read the downloaded encrypted data.
    with open(download_filename, 'rb') as f:
        nonce_length = int.from_bytes(f.read(1), 'big')
        nonce_dl = f.read(nonce_length)
        tag_length = int.from_bytes(f.read(1), 'big')
        tag_dl = f.read(tag_length)
        ciphertext_dl = f.read()
    
    # === CP-ABE Policy Check (Access Control) ===
    # In this simulation, we simply check the user attributes before decryption.
    # Prompt the user for attributes.
    user_input = input("\nEnter your attributes (comma-separated, e.g., Manager,Finance,HR): ")
    user_attributes = {attr.strip() for attr in user_input.split(',')}
    
    if policy_example(user_attributes):
        try:
            decrypted_message = decrypt_message_aes(aes_key, nonce_dl, ciphertext_dl, tag_dl)
            print("\n[AES] Decryption succeeded. Decrypted Message:")
            print(decrypted_message)
        except Exception as e:
            print("\n[AES] Decryption failed:", e)
    else:
        raise Exception("Access denied: user attributes do not satisfy the CP-ABE policy.")

if __name__ == "__main__":
    main()
