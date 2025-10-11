# Image Steganography Project

Welcome to the **Image Steganography** project! This project explores techniques to hide secret messages inside images, combining security, usability, and a touch of digital magic. It features both **naive pixel-based embedding** and **Least Significant Bit (LSB) steganography**.

---

## Features

### LSB Steganography (`steganography_lsb.py`)
- Hides messages in the **least significant bits** of image pixels, minimizing visual distortion.
- Password-protected messages using hashed verification.
- GUI built with **Tkinter** for easy interaction:
  - Select an image
  - Enter a secret message
  - Set a password (with optional visibility toggle)
  - Encrypt and decrypt with a single click
  - Automatic closure of the window after completion

### Naive Steganography (`steganography_naive.py`)
- Directly modifies pixel values to embed message characters.
- Provides a simple GUI for experimentation and educational purposes.
- Less secure than LSB method, but helps understand the basics of steganography.

### Forensics Tool (`steg_forensics.py`)
- Detects hidden messages in images using:
  - Magic headers
  - LSB analysis
  - Entropy calculations of LSBs
- Provides quick feedback on whether an image may contain hidden data.

---

## How it Works

- **LSB Steganography:** The secret message is converted to binary and hidden in the least significant bit of each pixel. A password is hashed and stored securely within the image for authentication.
- **Decryption:** The LSBs are read from the image to reconstruct the message. Only the correct password will reveal the message fully, ensuring security.
- **Naive Method:** Each character of the message is directly embedded into pixel values sequentially. This method is less secure and may include extra characters after the message.

---

## Setup Instructions

Follow these steps to set up and run this project locally:

### 1. Clone the repository
```bash
git clone <repository_url>
cd Steganography-Edunet_Cybersecurity-Internship-2025
```

### 2. Create a Conda environment with Python 3.11
```bash
conda create -n steganography python=3.11 -y
conda activate steganography
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the LSB Steganography GUI
```bash
python steganography_lsb.py
```

### 5. Forensics scan:
```bash
python steg_forensics.py <image_path>
```

## Project Structure

.
├── steganography_lsb.py       # LSB-based GUI steganography

├── steganography_naive.py     # Naive pixel-based steganography

├── steg_forensics.py          # LSB + entropy-based detection


├── requirements.txt           # Required Python packages

├── README.md                  # Project documentation

├── encryptedImage_LSB.png     # Example encrypted image

├── *.jpg / *.png              # Sample input images
