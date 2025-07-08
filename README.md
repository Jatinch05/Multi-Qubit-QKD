# Multi-Qubit QKD with CP-ABE and Cloud-Backed Secure Storage

This project demonstrates a **hybrid cryptographic system** that combines:
- **Quantum Key Distribution (QKD)** using Qiskit
- **Chaotic entropy** to improve randomness
- **Attribute-Based Encryption (CP-ABE)** for access control
- **AES encryption** for confidentiality
- **AWS S3** for cloud storage and retrieval

---

## 🔒 Project Objective

To simulate a real-world quantum-secured cloud system where:
- Alice generates and sends entangled qubits.
- Bob receives and measures them to derive a shared key.
- The message is encrypted using AES with the derived key.
- The ciphertext is protected by a CP-ABE access policy.
- Data is uploaded to and retrieved from AWS S3 securely.

---

## 📁 Directory Structure

```
.
├── alice.py             # Qubit generation with chaotic Bell states
├── bob.py               # Measurement logic for Bob
├── common.py            # Chaotic angle generation (logistic map)
├── cpabe.py             # CP-ABE encryption and attribute-based checks
├── main.py              # Main orchestrator: QKD + CP-ABE + AES + S3
├── encrypted_data.bin   # Example encrypted output file
├── requirements.txt     # All dependencies
└── README.md            # This file
```

---

## 🧠 Background Concepts

| Concept     | Description |
|-------------|-------------|
| **QKD**     | Quantum Key Distribution is used to securely generate a shared secret key between two parties using quantum states. |
| **Chaos**   | The logistic map introduces unpredictability in quantum state rotations. |
| **CP-ABE**  | Ciphertext Policy Attribute-Based Encryption restricts access based on user attributes. |
| **AES**     | A fast symmetric cipher used here for message encryption. |
| **S3**      | Amazon's cloud storage service is used to upload encrypted data. |

---

## 🧪 How It Works

1. **QKD Simulation**:
   - Alice prepares chaotic Bell states.
   - Bob measures them to derive a key.

2. **Symmetric Encryption**:
   - AES-128 encrypts the plaintext using the QKD-derived key.

3. **Access Control with CP-ABE**:
   - Before decryption, a user’s attributes are verified against the ciphertext’s policy.

4. **Cloud Integration**:
   - Encrypted data is uploaded to **AWS S3**.
   - On request, it's downloaded and decrypted locally if policy matches.

---

## ⚙️ Setup Instructions

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install Qiskit (if not done already)

```bash
pip install qiskit qiskit-aer
```

### 3. AWS Credentials

Ensure your AWS credentials are configured:
```bash
aws configure
```

Required IAM permissions:
```json
{
  "Effect": "Allow",
  "Action": ["s3:PutObject", "s3:GetObject"],
  "Resource": "arn:aws:s3:::your-bucket-name/*"
}
```

---

## 🚀 Running the Project

```bash
python main.py
```

Sample output:
- Derived AES key
- CP-ABE validation result
- AES ciphertext
- Encrypted file upload to S3

---

## 🧾 Example CP-ABE Policy

```python
def policy_example(attributes):
    required = {"Manager", "Finance"}
    return required.issubset(attributes)
```

---

## ☁️ Cloud Setup

Ensure your bucket exists in S3:
- Access policy grants PutObject/GetObject

---

## 📊 Possible Enhancements

- Error correction simulation between Alice and Bob
- Real quantum backend testing
- Add logs or audit trails for key requests
- Extend CP-ABE with fine-grained policy language
- Host frontend for cloud access requests

---

## 🧠 Credits

Inspired by research in:
- “Multi-Qubit Chaotic Quantum Key Distribution with Attribute-Based Encryption”
- NIST Post-Quantum Cryptography standards
- Qiskit documentation and AWS SDK

---

## 📜 License

MIT License