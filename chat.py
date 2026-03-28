import socket
import threading
import struct
import os
import queue
import time
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import tkinter as tk
from tkinter import scrolledtext

port = 5000
block_size = 256

def send_packet(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_packet(sock):
    def recvall(n):
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    raw_len = recvall(4)
    if not raw_len:
        return None

    return recvall(struct.unpack(">I", raw_len)[0])

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=200000)

def encrypt(key, msg):
    data = msg.encode()
    length = min(len(data), block_size - 2)
    payload = length.to_bytes(2, 'big') + data[:length]
    payload += os.urandom(block_size - len(payload))

    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(payload)
    return cipher.nonce + tag + ct

def decrypt(key, data):
    nonce, tag, ct = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)

    length = int.from_bytes(pt[:2], 'big')
    return pt[2:2+length].decode(errors="ignore")

def handshake_server(sock, password):
    salt = os.urandom(16)
    send_packet(sock, salt)

    key = derive_key(password, salt)

    challenge = os.urandom(16)
    send_packet(sock, challenge)

    response = recv_packet(sock)
    expected = hashlib.sha256(challenge + key).digest()

    if response != expected:
        raise Exception("auth failed")

    send_packet(sock, b"OK")
    return key

def handshake_client(sock, password):
    salt = recv_packet(sock)
    key = derive_key(password, salt)

    challenge = recv_packet(sock)
    send_packet(sock, hashlib.sha256(challenge + key).digest())

    if recv_packet(sock) != b"OK":
        raise Exception("auth failed")

    return key

class ChatGUI:
    def __init__(self, sock, key, mode):
        self.sock = sock
        self.key = key
        self.queue = queue.Queue()
        self.root = tk.Tk()
        self.root.title(f"encrypted chat ({mode})")
        self.root.configure(bg="#0a0a0a")
        self.root.geometry("700x520")

        self.chat = scrolledtext.ScrolledText(
            self.root, state='disabled', bg="#0a0a0a", fg="#e0e0e0", 
            font=("TkDefaultFont", 11), height=22, wrap=tk.WORD,
            relief="flat", bd=0
        )
        self.chat.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)

        input_frame = tk.Frame(self.root, bg="#0a0a0a")
        input_frame.pack(fill=tk.X, padx=15, pady=8)

        self.entry = tk.Entry(input_frame, bg="#1a1a1a", fg="#e0e0e0", 
                             font=("TkDefaultFont", 11), relief="flat", bd=0)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)

        self.entry.bind("<Return>", self.send)
        
        threading.Thread(target=self.receive, daemon=True).start()
        self.root.after(100, self.update)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.mainloop()

    def update(self):
        while not self.queue.empty():
            self.chat.config(state='normal')
            self.chat.insert(tk.END, self.queue.get() + "\n")
            self.chat.config(state='disabled')
            self.chat.see(tk.END)
        self.root.after(100, self.update)

    def receive(self):
        while True:
            try:
                data = recv_packet(self.sock)
                if not data:
                    break
                self.queue.put(f"peer - {decrypt(self.key, data)}")
            except:
                break
        self.queue.put("(disconnected)")

    def send(self, event=None):
        msg = self.entry.get().strip()
        if msg:
            try:
                time.sleep(random.uniform(0.05, 0.2))
                send_packet(self.sock, encrypt(self.key, msg))
                self.queue.put(f"you - {msg}")
            except:
                self.queue.put("(send error)")
            self.entry.delete(0, tk.END)

    def close(self):
        try:
            self.sock.close()
        finally:
            self.root.destroy()

def start_server(password):
    s = socket.socket()
    s.bind(("0.0.0.0", port))
    s.listen(1)
    print("listening...")

    conn, _ = s.accept()
    key = handshake_server(conn, password)
    del password

    ChatGUI(conn, key, "listen")

def start_client(ip, password):
    s = socket.socket()
    s.connect((ip, port))

    key = handshake_client(s, password)
    del password

    ChatGUI(s, key, "connect")

password = input("shared password: ").encode()
mode = input("mode (listen/connect): ").strip()

if mode == "listen":
    start_server(password)
else:
    start_client(input("peer: ").strip(), password)
