import cv2
import numpy as np
import os
import sys

MAGIC_HEADER = "STEG"

def extract_lsb_bits(img):
    """Flatten image and extract least significant bits"""
    flat = img.flatten()
    bits = [pixel & 1 for pixel in flat]
    return bits

def bits_to_string(bits, max_chars=10000):
    """Convert bits to string, up to max_chars"""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        chars.append(chr(int(''.join(map(str, byte)), 2)))
        if len(chars) >= max_chars:
            break
    return ''.join(chars)

def check_for_hidden_message(img_path):
    img = cv2.imread(img_path)
    if img is None:
        print(f"[!] Could not load image: {img_path}")
        return
    
    print(f"Loaded: {img_path} | shape={img.shape}")
    
    # Extract LSBs
    bits = extract_lsb_bits(img)
    recovered = bits_to_string(bits)
    
    if MAGIC_HEADER in recovered:
        start_idx = recovered.find(MAGIC_HEADER)
        message = recovered[start_idx + len(MAGIC_HEADER):]
        print(f"[+] Hidden message detected! First 200 chars:\n{message[:200]}")
        return True
    else:
        print("[*] No hidden message detected using LSB + magic header.")
        return False

def compute_lsb_entropy(img):
    bits = extract_lsb_bits(img)
    p0 = bits.count(0) / len(bits)
    p1 = bits.count(1) / len(bits)
    entropy = 0
    for p in [p0, p1]:
        if p > 0:
            entropy -= p * np.log2(p)
    return entropy

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <image_path>")
        return
    img_path = sys.argv[1]
    
    detected = check_for_hidden_message(img_path)
    
    # Optional: LSB entropy as additional evidence
    img = cv2.imread(img_path)
    entropy = compute_lsb_entropy(img)
    print(f"LSB entropy: {entropy:.4f}")
    
    if detected:
        print("[*] Forensic scan completed: hidden message detected.")
    else:
        print("[*] Forensic scan completed: no hidden message detected.")

if __name__ == "__main__":
    main()
