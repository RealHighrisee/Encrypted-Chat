# Encrypted Chat

### Features
- AES-256-GCM encryption
- PBKDF2 key derivation (200,000 iterations)
- Secure handshake with challenge-response

### Network
- Works only in the **same local network** by default.
- To connect from different networks, use **Radmin VPN** (or any other VPN that creates a shared LAN).

### How to use
1. Both parties run the same Python script
2. Enter the same shared password
3. One chooses `listen`, the other `connect` and enters the peer **IPv4** address

### Requirements
- Python 3
- pycryptodome
- tkinter
