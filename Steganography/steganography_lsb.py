import cv2
import os
import platform
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
import hashlib

class SteganographyLSBApp:
    SENTINEL = "<END>"  # Marks the end of hidden message

    def __init__(self, root):
        self.root = root
        self.root.title("LSB Image Steganography")
        self.root.geometry("600x550")
        self.root.resizable(False, False)
        
        self.image_path = ""
        self.show_password = tk.BooleanVar(value=False)
        
        # --- Main Frame ---
        frame = tk.Frame(root, padx=20, pady=20)
        frame.pack(expand=True)
        
        # --- Image Selection ---
        tk.Label(frame, text="Select an Image:", font=("Arial", 12)).grid(row=0, column=0, sticky="w")
        self.select_btn = tk.Button(frame, text="Browse", command=self.select_image, width=15)
        self.select_btn.grid(row=0, column=1, padx=10)
        self.file_label = tk.Label(frame, text="No file selected", fg="blue", font=("Arial", 10))
        self.file_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0,10))
        
        # --- Image Preview Area ---
        self.preview_label = tk.Label(frame)
        self.preview_label.grid(row=2, column=0, columnspan=2, pady=(5,15))
        
        # --- Message Entry ---
        tk.Label(frame, text="Enter Secret Message:", font=("Arial", 12)).grid(row=3, column=0, sticky="w")
        self.msg_entry = tk.Entry(frame, width=40, font=("Arial", 10))
        self.msg_entry.grid(row=3, column=1, pady=5)
        
        # --- Password Entry ---
        tk.Label(frame, text="Enter Passcode:", font=("Arial", 12)).grid(row=4, column=0, sticky="w")
        self.pass_entry = tk.Entry(frame, show='*', width=40, font=("Arial", 10))
        self.pass_entry.grid(row=4, column=1, pady=5)
        
        # --- Toggle Password Visibility ---
        self.toggle_btn = tk.Checkbutton(frame, text="Show Password", variable=self.show_password, 
                                         command=self.toggle_password, font=("Arial", 10))
        self.toggle_btn.grid(row=5, column=1, sticky="w", pady=(0,10))
        
        # --- Buttons ---
        self.encrypt_btn = tk.Button(frame, text="Encrypt & Save", command=self.encrypt_message,
                                     width=20, bg="#4CAF50", fg="white", font=("Arial", 11))
        self.encrypt_btn.grid(row=6, column=0, pady=10)
        self.decrypt_btn = tk.Button(frame, text="Decrypt", command=self.decrypt_message,
                                     width=20, bg="#2196F3", fg="white", font=("Arial", 11))
        self.decrypt_btn.grid(row=6, column=1, pady=10)
    
    # ---------------------- GUI FUNCTIONS ----------------------
    def select_image(self):
        self.image_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp *.tiff")]
        )
        if self.image_path:
            filename = os.path.basename(self.image_path)
            self.file_label.config(text=f"Selected: {filename}")
            self.show_preview(self.image_path)
            messagebox.showinfo("Image Selected", f"Selected: {self.image_path}")
        else:
            self.file_label.config(text="No file selected")

    def show_preview(self, path):
        try:
            img = Image.open(path)
            img.thumbnail((250, 250))
            img_tk = ImageTk.PhotoImage(img)
            self.preview_label.config(image=img_tk)
            self.preview_label.image = img_tk
        except Exception as e:
            self.preview_label.config(image='', text="Preview unavailable", fg="red")
            print("Preview error:", e)

    def toggle_password(self):
        self.pass_entry.config(show='' if self.show_password.get() else '*')

    def _message_to_bits(self, msg):
        return [int(bit) for char in msg for bit in format(ord(char), '08b')]

    def _bits_to_message(self, bits):
        chars = []
        for b in range(0, len(bits), 8):
            byte = bits[b:b+8]
            if len(byte) < 8:
                break
            chars.append(chr(int(''.join(map(str, byte)), 2)))
        return ''.join(chars)
    
    # ---------------------- ENCRYPTION ----------------------
    def encrypt_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        
        msg = self.msg_entry.get()
        password = self.pass_entry.get()
        if not msg or not password:
            messagebox.showerror("Error", "Message and Passcode cannot be empty.")
            return
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
        msg_to_hide = f"STEG|{password_hash}|{msg}{self.SENTINEL}"
        
        img = cv2.imread(self.image_path)
        if img is None:
            messagebox.showerror("Error", "Unable to open image file.")
            return

        bits = self._message_to_bits(msg_to_hide)
        total_pixels = img.shape[0] * img.shape[1] * 3
        if len(bits) > total_pixels:
            messagebox.showerror("Error", "Message too long for this image.")
            return
        
        flat_img = img.flatten()
        for i, bit in enumerate(bits):
            flat_img[i] = (flat_img[i] & 0b11111110) | bit
        encrypted_img = flat_img.reshape(img.shape)
        
        encrypted_path = os.path.join(os.getcwd(), "encryptedImage_LSB.png")
        cv2.imwrite(encrypted_path, encrypted_img)
        self._open_file(encrypted_path)
        messagebox.showinfo("Success", f"Message Encrypted & Saved:\n{encrypted_path}")
        self.root.destroy()
    
    # ---------------------- DECRYPTION ----------------------
    def decrypt_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        
        entered_pass = self.pass_entry.get()
        img = cv2.imread(self.image_path)
        if img is None:
            messagebox.showerror("Error", "Unable to open image file.")
            return
        
        flat_img = img.flatten()
        bits = [pixel & 1 for pixel in flat_img]
        message = self._bits_to_message(bits)
        
        if not message.startswith("STEG|"):
            messagebox.showerror("Error", "No hidden message detected.")
            return
        
        try:
            _, stored_hash, hidden_msg_with_sentinel = message.split("|", 2)
            if hashlib.sha256(entered_pass.encode()).hexdigest()[:16] != stored_hash:
                messagebox.showerror("Error", "Incorrect Passcode.")
                return
            
            hidden_msg = hidden_msg_with_sentinel.split(self.SENTINEL)[0]
            messagebox.showinfo("Decryption Successful", f"Decrypted Message:\n{hidden_msg}")
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed.")
            print("Decryption error:", e)
    
    # ---------------------- OS-INDEPENDENT FILE OPEN ----------------------
    def _open_file(self, path):
        try:
            system = platform.system()
            if system == "Windows":
                os.system(f'start "" "{path}"')
            elif system == "Darwin":  # macOS
                os.system(f'open "{path}"')
            else:  # Linux / Ubuntu
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            print("Could not open file automatically:", e)

# ---------------------- RUN APP ----------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyLSBApp(root)
    root.mainloop()
