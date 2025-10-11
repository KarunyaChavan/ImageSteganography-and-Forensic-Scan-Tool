import cv2
import os
import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Encoding dictionary
d = {chr(i): i for i in range(255)}
c = {i: chr(i) for i in range(255)}

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography")
        self.root.geometry("400x300")
        
        self.image_path = ""
        self.password = ""
        
        tk.Label(root, text="Select an Image").pack()
        self.select_btn = tk.Button(root, text="Browse", command=self.select_image)
        self.select_btn.pack()
        
        self.file_label = tk.Label(root, text="No file selected", fg="blue")
        self.file_label.pack()
        
        tk.Label(root, text="Enter Secret Message").pack()
        self.msg_entry = tk.Entry(root, width=50)
        self.msg_entry.pack()
        
        tk.Label(root, text="Enter Passcode").pack()
        self.pass_entry = tk.Entry(root, show='*', width=50)
        self.pass_entry.pack()
        
        self.encrypt_btn = tk.Button(root, text="Encrypt & Save", command=self.encrypt_message)
        self.encrypt_btn.pack()
        
        self.decrypt_btn = tk.Button(root, text="Decrypt", command=self.decrypt_message)
        self.decrypt_btn.pack()
    
    def select_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.png")])
        if self.image_path:
            self.file_label.config(text=f"Selected: {os.path.basename(self.image_path)}")
            messagebox.showinfo("Image Selected", f"Selected: {self.image_path}")
    
    def encrypt_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        
        msg = self.msg_entry.get()
        self.password = self.pass_entry.get()
        if not msg or not self.password:
            messagebox.showerror("Error", "Message and Passcode cannot be empty.")
            return
        
        img = cv2.imread(self.image_path)
        n, m, z = 0, 0, 0
        
        for char in msg:
            img[n, m, z] = d[char]
            n = (n + 1) % img.shape[0]
            m = (m + 1) % img.shape[1]
            z = (z + 1) % 3
        
        encrypted_path = "encryptedImage.png"
        cv2.imwrite(encrypted_path, img)
        os.system(f"start {encrypted_path}")
        messagebox.showinfo("Success", "Message Encrypted & Image Saved!")
    
    def decrypt_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        
        entered_pass = self.pass_entry.get()
        if entered_pass != self.password:
            messagebox.showerror("Error", "Incorrect Passcode.")
            return
        
        img = cv2.imread(self.image_path)
        n, m, z = 0, 0, 0
        message = ""
        
        try:
            for _ in range(img.shape[0] * img.shape[1] * 3):  # Ensure we check all pixels
                char_value = img[n, m, z]
                if char_value in c:
                    message += c[char_value]
                else:
                    break
                n = (n + 1) % img.shape[0]
                m = (m + 1) % img.shape[1]
                z = (z + 1) % 3
            
            messagebox.showinfo("Decryption Successful", f"Decrypted Message: {message}")
        except:
            messagebox.showerror("Error", "Decryption failed.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
