# Bitvault 

> [!IMPORTANT]
> **Bitvault is currently under active development.** Features and security protocols are subject to change.

---

## System Overview

**Bitvault** is a high-security, local-offline password manager designed for those who prioritize data sovereignty and cryptographic excellence. Built with a focus on **AES-256** confidentiality and **HMAC** integrity, Bitvault ensures your sensitive information remains yours and yours alone.

### Cryptographic Foundation

Bitvault leverages industry standard primitives to provide a robust security posture:

*   **AES-256 (CBC Mode):** Uses Advanced Encryption Standard with a 256-bit key length. 256 bits provides $2^{256}$ possible combinations, making brute force attacks computationally infeasible.
*   **Initialization Vector (IV):** Every encryption operation uses a unique, random IV. This prevents "pattern leaking" where identical pieces of data would otherwise result in identical ciphertexts, ensuring that even if you store the same password twice, they look completely different on disk.
*   **HMAC (Hash-based Message Authentication Code):** To prevent tampering, Bitvault uses HMAC for data integrity. This ensures that any unauthorized modification to your vault, even a single bit, will be detected, preventing "bit-flipping" attacks.

### Why Local-Offline?

In an era of cloud breaches and "always-on" connectivity, Bitvault takes a different approach. By keeping your data strictly local and offline, eliminating entire classes of remote attack vectors. Your vault never leaves your machine unless you move it yourself.

---

## Getting Started

### Prerequisites

*   **CMake** (3.10 or higher)
*   **C++ Compiler** (GCC/Clang)
*   **Make**

### Build & Installation

Follow these steps to build and install Bitvault to your system's binary folder:

```bash
# 1. Create a build directory
mkdir build
cd build

# 2. Configure the project
cmake ..

# 3. Build the executable
make

# 4. Install to /usr/local/bin
sudo make install
```

Once installed, you can run `bitvault` from anywhere in your terminal.

---

<p align="center">
  <i>"Confidentiality is not a feature, it's a right."</i>
</p>


