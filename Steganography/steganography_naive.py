import cv2
import os
import platform
import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Crypto imports (PyCryptodome)
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import struct

# Encoding dicts (support full 0-255)
d = {chr(i): i for i in range(256)}
c = {i: chr(i) for i in range(256)}

class SteganographyApp:
    # Header to identify our embedded payload and version
    HEADER = b"STEG1"            # 5 bytes
    HEADER_LEN = len(HEADER)
    LEN_FIELD_SIZE = 4           # 4 bytes for payload length (big-endian)
    SALT_SIZE = 16               # PBKDF2 salt size
    NONCE_SIZE = 12              # AES-GCM recommended nonce
    TAG_SIZE = 16                # GCM tag size
    PBKDF2_ITERS = 100_000      # iterations for PBKDF2

    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography (AES-GCM)")
        self.root.geometry("420x320")
        self.root.resizable(False, False)
        
        self.image_path = ""
        
        tk.Label(root, text="Select an Image").pack(pady=(10, 0))
        self.select_btn = tk.Button(root, text="Browse", command=self.select_image)
        self.select_btn.pack()
        
        self.file_label = tk.Label(root, text="No file selected", fg="blue")
        self.file_label.pack(pady=(5, 10))
        
        tk.Label(root, text="Enter Secret Message").pack()
        self.msg_entry = tk.Entry(root, width=55)
        self.msg_entry.pack(pady=(0, 10))
        
        tk.Label(root, text="Enter Passcode").pack()
        self.pass_entry = tk.Entry(root, show='*', width=55)
        self.pass_entry.pack(pady=(0, 10))
        
        self.encrypt_btn = tk.Button(root, text="Encrypt & Save", command=self.encrypt_message)
        self.encrypt_btn.pack(pady=(5, 5))
        
        self.decrypt_btn = tk.Button(root, text="Decrypt", command=self.decrypt_message)
        self.decrypt_btn.pack(pady=(0, 10))
    
    # ---------------------- IMAGE SELECTION ----------------------
    def select_image(self):
        self.image_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp *.tiff")]
        )
        if self.image_path:
            self.file_label.config(text=f"Selected: {os.path.basename(self.image_path)}")
            messagebox.showinfo("Image Selected", f"Selected: {self.image_path}")
        else:
            self.file_label.config(text="No file selected")

    # ---------------------- UTIL: open file cross-platform ----------------------
    def _open_file(self, path):
        try:
            system = platform.system()
            if system == "Windows":
                os.system(f'start "" "{path}"')
            elif system == "Darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            print("Could not open file automatically:", e)

    # ---------------------- ENCRYPTION (secure) ----------------------
    def encrypt_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image.")
            return

        msg_text = self.msg_entry.get()
        password = self.pass_entry.get()
        if not msg_text or not password:
            messagebox.showerror("Error", "Message and Passcode cannot be empty.")
            return
        
        # Convert message to bytes (utf-8 allows unicode)
        plaintext = msg_text.encode("utf-8")
        
        # Generate salt and derive key (PBKDF2)
        salt = get_random_bytes(self.SALT_SIZE)
        key = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=self.PBKDF2_ITERS)
        
        # Encrypt with AES-GCM
        nonce = get_random_bytes(self.NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Build payload: salt || nonce || tag || ciphertext
        payload = salt + nonce + tag + ciphertext
        payload_len = len(payload)
        
        # Full bytes to embed: HEADER || payload_len (4 bytes) || payload
        full = self.HEADER + struct.pack(">I", payload_len) + payload  # big-endian length
        
        # Read image
        img = cv2.imread(self.image_path)
        if img is None:
            messagebox.showerror("Error", "Unable to open image file.")
            return
        
        capacity = img.shape[0] * img.shape[1] * 3
        if len(full) > capacity:
            messagebox.showerror(
                "Error",
                f"Payload ({len(full)} bytes) too large for image capacity ({capacity} bytes)."
            )
            return
        
        # Embed payload bytes into pixel channels sequentially
        flat = img.flatten()
        for i, byte in enumerate(full):
            flat[i] = byte  # store exact byte 0-255
        embedded = flat.reshape(img.shape)
        
        encrypted_path = os.path.join(os.getcwd(), "encryptedImage.png")
        cv2.imwrite(encrypted_path, embedded)
        self._open_file(encrypted_path)
        messagebox.showinfo("Success", f"Encrypted message saved to:\n{encrypted_path}")

    # ---------------------- DECRYPTION (secure) ----------------------
    def decrypt_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image.")
            return

        password = self.pass_entry.get()
        if not password:
            messagebox.showerror("Error", "Enter the passcode used when encrypting.")
            return
        
        img = cv2.imread(self.image_path)
        if img is None:
            messagebox.showerror("Error", "Unable to open image file.")
            return
        
        flat = img.flatten()
        
        # Read header
        if len(flat) < self.HEADER_LEN + self.LEN_FIELD_SIZE:
            messagebox.showerror("Error", "Image does not contain embedded data.")
            return
        
        header_bytes = bytes(flat[: self.HEADER_LEN].tolist())
        if header_bytes != self.HEADER:
            messagebox.showerror("Error", "No valid embedded payload found.")
            return
        
        # Read length (next 4 bytes)
        length_bytes = bytes(flat[self.HEADER_LEN: self.HEADER_LEN + self.LEN_FIELD_SIZE].tolist())
        payload_len = struct.unpack(">I", length_bytes)[0]
        
        total_needed = self.HEADER_LEN + self.LEN_FIELD_SIZE + payload_len
        if total_needed > len(flat):
            messagebox.showerror("Error", "Embedded payload length is invalid/corrupted.")
            return
        
        payload_start = self.HEADER_LEN + self.LEN_FIELD_SIZE
        payload_bytes = bytes(flat[payload_start: payload_start + payload_len].tolist())
        
        # Parse payload: salt || nonce || tag || ciphertext
        if len(payload_bytes) < (self.SALT_SIZE + self.NONCE_SIZE + self.TAG_SIZE):
            messagebox.showerror("Error", "Embedded payload is too small/corrupted.")
            return
        
        salt = payload_bytes[0:self.SALT_SIZE]
        nonce = payload_bytes[self.SALT_SIZE: self.SALT_SIZE + self.NONCE_SIZE]
        tag = payload_bytes[self.SALT_SIZE + self.NONCE_SIZE: self.SALT_SIZE + self.NONCE_SIZE + self.TAG_SIZE]
        ciphertext = payload_bytes[self.SALT_SIZE + self.NONCE_SIZE + self.TAG_SIZE :]
        
        # Derive key from provided password + extracted salt
        key = PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=self.PBKDF2_ITERS)
        
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            message_text = plaintext.decode("utf-8")
            messagebox.showinfo("Decryption Successful", f"Decrypted Message:\n{message_text}")
        except Exception as e:
            # On wrong password or tampering, AES-GCM verify fails
            print("Decryption error:", e)
            messagebox.showerror("Error", "Decryption failed — wrong passcode or tampered data.")

# ---------------------- MAIN ----------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
