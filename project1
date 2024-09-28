"""
Author: Tala Bashanfar
Date: July 26,2024
Student Number: 100914973

This program implements a cipher game where users can encrypt messages using various encryption algorithms:
- Caesar Cipher
- Substitution Cipher
- Playfair Cipher
- Transposition Cipher
- Product Cipher
- RSA Cipher

The program includes a graphical user interface (GUI) using Tkinter for user interaction.
"""

import random
import string

class Message:
    def __init__(self, text):
        self._text = text

    @property
    def text(self):
        return self._text

    def apply_cipher(self, cipher):
        raise NotImplementedError("This method should be overridden in derived classes")

class PlaintextMsg(Message):
    def encrypt(self, cipher):
        return cipher.encrypt(self._text)

class CiphertextMsg(Message):
    def decrypt(self, cipher):
        return cipher.decrypt(self._text)

# Example Cipher: Caesar Cipher
class CaesarCipher:
    def __init__(self, shift):
        self.shift = shift % 26

    def encrypt(self, plaintext):
        return ''.join(
            chr((ord(char) - 65 + self.shift) % 26 + 65) if char.isupper() else
            chr((ord(char) - 97 + self.shift) % 26 + 97) if char.islower() else char
            for char in plaintext
        )

    def decrypt(self, ciphertext):
        return ''.join(
            chr((ord(char) - 65 - self.shift) % 26 + 65) if char.isupper() else
            chr((ord(char) - 97 - self.shift) % 26 + 97) if char.islower() else char
            for char in ciphertext
        )

# Substitution Cipher
class SubstitutionCipher:
    def __init__(self, key):
        self.key = key
        self.inverse_key = {v: k for k, v in key.items()}

    def encrypt(self, plaintext):
        return ''.join(self.key.get(char, char) for char in plaintext)

    def decrypt(self, ciphertext):
        return ''.join(self.inverse_key.get(char, char) for char in ciphertext)

# Playfair Cipher
class PlayfairCipher:
    def __init__(self, key):
        self.key = key
        self.matrix = self.generate_matrix(key)
        
    def generate_matrix(self, key):
        key = ''.join(sorted(set(key), key=lambda x: key.index(x)))  # Remove duplicates
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        matrix = ''.join([c for c in key if c in alphabet] + [c for c in alphabet if c not in key])
        return [matrix[i:i+5] for i in range(0, 25, 5)]

    def preprocess(self, text):
        text = text.replace('J', 'I')
        processed = []
        i = 0
        while i < len(text):
            a = text[i]
            b = text[i+1] if i+1 < len(text) else 'X'
            if a == b:
                processed.append(a + 'X')
                i += 1
            else:
                processed.append(a + b)
                i += 2
        if len(processed[-1]) == 1:
            processed[-1] += 'X'
        return processed

    def find_position(self, char):
        for row in range(5):
            for col in range(5):
                if self.matrix[row][col] == char:
                    return row, col

    def encrypt_pair(self, a, b):
        row1, col1 = self.find_position(a)
        row2, col2 = self.find_position(b)
        if row1 == row2:
            return self.matrix[row1][(col1+1) % 5] + self.matrix[row2][(col2+1) % 5]
        elif col1 == col2:
            return self.matrix[(row1+1) % 5][col1] + self.matrix[(row2+1) % 5][col2]
        else:
            return self.matrix[row1][col2] + self.matrix[row2][col1]

    def decrypt_pair(self, a, b):
        row1, col1 = self.find_position(a)
        row2, col2 = self.find_position(b)
        if row1 == row2:
            return self.matrix[row1][(col1-1) % 5] + self.matrix[row2][(col2-1) % 5]
        elif col1 == col2:
            return self.matrix[(row1-1) % 5][col1] + self.matrix[(row2-1) % 5][col2]
        else:
            return self.matrix[row1][col1] + self.matrix[row2][col2]

    def encrypt(self, plaintext):
        plaintext = plaintext.upper().replace(' ', '')
        pairs = self.preprocess(plaintext)
        return ''.join(self.encrypt_pair(a, b) for a, b in pairs)

    def decrypt(self, ciphertext):
        pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
        return ''.join(self.decrypt_pair(a, b) for a, b in pairs)

# Transposition Cipher
class TranspositionCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        ciphertext = [''] * len(self.key)
        for i, char in enumerate(plaintext):
            ciphertext[i % len(self.key)] += char
        return ''.join(ciphertext)

    def decrypt(self, ciphertext):
        num_columns = len(ciphertext) // len(self.key)
        num_rows = len(self.key)
        plaintext = [''] * num_columns
        for i in range(num_columns):
            for j in range(num_rows):
                plaintext[i] += ciphertext[i * num_rows + j]
        return ''.join(plaintext)

# Product Cipher (Combining two or more ciphers)
class ProductCipher:
    def __init__(self, ciphers):
        self.ciphers = ciphers

    def encrypt(self, plaintext):
        for cipher in self.ciphers:
            plaintext = cipher.encrypt(plaintext)
        return plaintext

    def decrypt(self, ciphertext):
        for cipher in reversed(self.ciphers):
            ciphertext = cipher.decrypt(ciphertext)
        return ciphertext

# RSA Cipher (Simplified for educational purposes)
class RSACipher:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

    def encrypt(self, plaintext):
        return ''.join(chr((ord(char) ** self.public_key[0]) % self.public_key[1]) for char in plaintext)

    def decrypt(self, ciphertext):
        return ''.join(chr((ord(char) ** self.private_key[0]) % self.private_key[1]) for char in ciphertext)
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher App")
        
        self.cipher_var = tk.StringVar()
        self.message_var = tk.StringVar()
        self.history = []
        
        ttk.Label(root, text="Select Cipher:").grid(column=0, row=0, padx=10, pady=10)
        self.cipher_menu = ttk.Combobox(root, textvariable=self.cipher_var)
        self.cipher_menu['values'] = ('Caesar', 'Substitution', 'Playfair', 'Transposition', 'Product', 'RSA')
        self.cipher_menu.grid(column=1, row=0, padx=10, pady=10)
        
        ttk.Label(root, text="Enter Message:").grid(column=0, row=1, padx=10, pady=10)
        self.message_entry = ttk.Entry(root, textvariable=self.message_var, width=50)
        self.message_entry.grid(column=1, row=1, padx=10, pady=10)
        
        self.encrypt_button = ttk.Button(root, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.grid(column=0, row=2, padx=10, pady=10)
        
        self.result_label = ttk.Label(root, text="")
        self.result_label.grid(column=1, row=2, padx=10, pady=10)
        
        self.history_display = scrolledtext.ScrolledText(root, width=70, height=15)
        self.history_display.grid(column=0, row=3, columnspan=2, padx=10, pady=10)
    
    def encrypt_message(self):
        cipher = self.cipher_var.get()
        message = self.message_var.get()
        
        if not message or not cipher:
            self.result_label.config(text="Please select a cipher and enter a message.")
            return
        
        if cipher == "Caesar":
            caesar_cipher = CaesarCipher(3)
            plaintext = PlaintextMsg(message)
            encrypted_message = plaintext.encrypt(caesar_cipher)
            self.history.append((message, encrypted_message, "Caesar"))
        elif cipher == "Substitution":
            key = {char: random.choice(string.ascii_uppercase) for char in string.ascii_uppercase}
            substitution_cipher = SubstitutionCipher(key)
            plaintext = PlaintextMsg(message)
            encrypted_message = plaintext.encrypt(substitution_cipher)
            self.history.append((message, encrypted_message, "Substitution"))
        elif cipher == "Playfair":
            playfair_cipher = PlayfairCipher("KEYWORD")
            plaintext = PlaintextMsg(message)
            encrypted_message = plaintext.encrypt(playfair_cipher)
            self.history.append((message, encrypted_message, "Playfair"))
        elif cipher == "Transposition":
            transposition_cipher = TranspositionCipher("KEY")
            plaintext = PlaintextMsg(message)
            encrypted_message = plaintext.encrypt(transposition_cipher)
            self.history.append((message, encrypted_message, "Transposition"))
        elif cipher == "Product":
            caesar_cipher = CaesarCipher(3)
            transposition_cipher = TranspositionCipher("KEY")
            product_cipher = ProductCipher([caesar_cipher, transposition_cipher])
            plaintext = PlaintextMsg(message)
            encrypted_message = plaintext.encrypt(product_cipher)
            self.history.append((message, encrypted_message, "Product"))
        elif cipher == "RSA":
            public_key = (65537, 3233)
            private_key = (2753, 3233)
            rsa_cipher = RSACipher(public_key, private_key)
            plaintext = PlaintextMsg(message)
            encrypted_message = plaintext.encrypt(rsa_cipher)
            self.history.append((message, encrypted_message, "RSA"))
        
        self.update_history_display()
        self.result_label.config(text=f"Encrypted Message: {encrypted_message}")
    
    def update_history_display(self):
        self.history_display.delete(1.0, tk.END)
        for original, encrypted, method in self.history:
            self.history_display.insert(tk.END, f"Original: {original}, Encrypted: {encrypted}, Method: {method}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
