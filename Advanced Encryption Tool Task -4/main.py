import os
import sys
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json

class AdvancedEncryptionTool:
    def __init__(self):
        self.backend = default_backend()
        
    def generate_key_from_password(self, password, salt):
        """Generate encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def encrypt_file_aes(self, input_file, output_file, password):
        """Encrypt file using AES-256-GCM"""
        try:
            # Generate random salt and IV
            salt = os.urandom(16)
            iv = os.urandom(12)  # GCM mode uses 96-bit IV
            
            # Generate key from password
            key = self.generate_key_from_password(password, salt)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            # Read and encrypt file
            with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Write metadata (salt, iv)
                outfile.write(salt)
                outfile.write(iv)
                
                # Encrypt file content
                while True:
                    chunk = infile.read(8192)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                
                # Finalize and write authentication tag
                encryptor.finalize()
                outfile.write(encryptor.tag)
            
            return True, "File encrypted successfully"
            
        except Exception as e:
            return False, f"Encryption failed: {str(e)}"
    
    def decrypt_file_aes(self, input_file, output_file, password):
        """Decrypt file using AES-256-GCM"""
        try:
            with open(input_file, 'rb') as infile:
                # Read metadata
                salt = infile.read(16)
                iv = infile.read(12)
                
                # Generate key from password
                key = self.generate_key_from_password(password, salt)
                
                # Read encrypted content and tag
                encrypted_data = infile.read()
                auth_tag = encrypted_data[-16:]  # Last 16 bytes
                encrypted_content = encrypted_data[:-16]
                
                # Create cipher and decrypt
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=self.backend)
                decryptor = cipher.decryptor()
                
                with open(output_file, 'wb') as outfile:
                    # Decrypt in chunks
                    for i in range(0, len(encrypted_content), 8192):
                        chunk = encrypted_content[i:i+8192]
                        decrypted_chunk = decryptor.update(chunk)
                        outfile.write(decrypted_chunk)
                    
                    decryptor.finalize()
            
            return True, "File decrypted successfully"
            
        except Exception as e:
            return False, f"Decryption failed: {str(e)}"
    
    def generate_rsa_keypair(self, key_size=2048):
        """Generate RSA key pair"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self.backend
            )
            public_key = private_key.public_key()
            
            return private_key, public_key
            
        except Exception as e:
            raise Exception(f"Key generation failed: {str(e)}")
    
    def save_rsa_keys(self, private_key, public_key, private_key_file, public_key_file, password=None):
        """Save RSA keys to files"""
        try:
            # Save private key
            if password:
                encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            else:
                encryption_algorithm = serialization.NoEncryption()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )
            
            with open(private_key_file, 'wb') as f:
                f.write(private_pem)
            
            # Save public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open(public_key_file, 'wb') as f:
                f.write(public_pem)
            
            return True, "Keys saved successfully"
            
        except Exception as e:
            return False, f"Failed to save keys: {str(e)}"
    
    def load_rsa_private_key(self, key_file, password=None):
        """Load RSA private key from file"""
        try:
            with open(key_file, 'rb') as f:
                key_data = f.read()
            
            if password:
                private_key = serialization.load_pem_private_key(
                    key_data, password=password.encode(), backend=self.backend
                )
            else:
                private_key = serialization.load_pem_private_key(
                    key_data, password=None, backend=self.backend
                )
            
            return private_key
            
        except Exception as e:
            raise Exception(f"Failed to load private key: {str(e)}")
    
    def load_rsa_public_key(self, key_file):
        """Load RSA public key from file"""
        try:
            with open(key_file, 'rb') as f:
                key_data = f.read()
            
            public_key = serialization.load_pem_public_key(key_data, backend=self.backend)
            return public_key
            
        except Exception as e:
            raise Exception(f"Failed to load public key: {str(e)}")
    
    def encrypt_file_rsa(self, input_file, output_file, public_key_file):
        """Encrypt file using RSA + AES hybrid encryption"""
        try:
            # Load public key
            public_key = self.load_rsa_public_key(public_key_file)
            
            # Generate random AES key
            aes_key = os.urandom(32)
            iv = os.urandom(12)
            
            # Encrypt AES key with RSA
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Encrypt file with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
                # Write encrypted AES key and IV
                outfile.write(len(encrypted_aes_key).to_bytes(4, byteorder='big'))
                outfile.write(encrypted_aes_key)
                outfile.write(iv)
                
                # Encrypt file content
                while True:
                    chunk = infile.read(8192)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                
                # Finalize and write authentication tag
                encryptor.finalize()
                outfile.write(encryptor.tag)
            
            return True, "File encrypted successfully with RSA"
            
        except Exception as e:
            return False, f"RSA encryption failed: {str(e)}"
    
    def decrypt_file_rsa(self, input_file, output_file, private_key_file, password=None):
        """Decrypt file using RSA + AES hybrid decryption"""
        try:
            # Load private key
            private_key = self.load_rsa_private_key(private_key_file, password)
            
            with open(input_file, 'rb') as infile:
                # Read encrypted AES key
                key_length = int.from_bytes(infile.read(4), byteorder='big')
                encrypted_aes_key = infile.read(key_length)
                iv = infile.read(12)
                
                # Decrypt AES key with RSA
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Read encrypted content and tag
                encrypted_data = infile.read()
                auth_tag = encrypted_data[-16:]
                encrypted_content = encrypted_data[:-16]
                
                # Decrypt with AES
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, auth_tag), backend=self.backend)
                decryptor = cipher.decryptor()
                
                with open(output_file, 'wb') as outfile:
                    for i in range(0, len(encrypted_content), 8192):
                        chunk = encrypted_content[i:i+8192]
                        decrypted_chunk = decryptor.update(chunk)
                        outfile.write(decrypted_chunk)
                    
                    decryptor.finalize()
            
            return True, "File decrypted successfully with RSA"
            
        except Exception as e:
            return False, f"RSA decryption failed: {str(e)}"

class EncryptionGUI:
    def __init__(self):
        self.encryption_tool = AdvancedEncryptionTool()
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the GUI interface"""
        self.root = tk.Tk()
        self.root.title("Advanced Encryption Tool")
        self.root.geometry("800x600")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # AES Encryption Tab
        self.create_aes_tab(notebook)
        
        # RSA Encryption Tab
        self.create_rsa_tab(notebook)
        
        # Key Generation Tab
        self.create_keygen_tab(notebook)
    
    def create_aes_tab(self, notebook):
        """Create AES encryption tab"""
        aes_frame = ttk.Frame(notebook)
        notebook.add(aes_frame, text="AES Encryption")
        
        # File selection
        ttk.Label(aes_frame, text="Input File:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.aes_input_var = tk.StringVar()
        ttk.Entry(aes_frame, textvariable=self.aes_input_var, width=60).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(aes_frame, text="Browse", command=self.browse_aes_input).grid(row=0, column=2, padx=5, pady=5)
        
        # Output file
        ttk.Label(aes_frame, text="Output File:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.aes_output_var = tk.StringVar()
        ttk.Entry(aes_frame, textvariable=self.aes_output_var, width=60).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(aes_frame, text="Browse", command=self.browse_aes_output).grid(row=1, column=2, padx=5, pady=5)
        
        # Password
        ttk.Label(aes_frame, text="Password:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.aes_password_var = tk.StringVar()
        ttk.Entry(aes_frame, textvariable=self.aes_password_var, show='*', width=60).grid(row=2, column=1, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(aes_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Encrypt", command=self.aes_encrypt).pack(side='left', padx=10)
        ttk.Button(button_frame, text="Decrypt", command=self.aes_decrypt).pack(side='left', padx=10)
        
        # Result text
        ttk.Label(aes_frame, text="Result:").grid(row=4, column=0, sticky='nw', padx=5, pady=5)
        self.aes_result_text = scrolledtext.ScrolledText(aes_frame, height=15, width=80)
        self.aes_result_text.grid(row=5, column=0, columnspan=3, padx=5, pady=5)
    
    def create_rsa_tab(self, notebook):
        """Create RSA encryption tab"""
        rsa_frame = ttk.Frame(notebook)
        notebook.add(rsa_frame, text="RSA Encryption")
        
        # File selection
        ttk.Label(rsa_frame, text="Input File:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.rsa_input_var = tk.StringVar()
        ttk.Entry(rsa_frame, textvariable=self.rsa_input_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(rsa_frame, text="Browse", command=self.browse_rsa_input).grid(row=0, column=2, padx=5, pady=5)
        
        # Output file
        ttk.Label(rsa_frame, text="Output File:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.rsa_output_var = tk.StringVar()
        ttk.Entry(rsa_frame, textvariable=self.rsa_output_var, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(rsa_frame, text="Browse", command=self.browse_rsa_output).grid(row=1, column=2, padx=5, pady=5)
        
        # Public key file
        ttk.Label(rsa_frame, text="Public Key:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.rsa_public_var = tk.StringVar()
        ttk.Entry(rsa_frame, textvariable=self.rsa_public_var, width=50).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(rsa_frame, text="Browse", command=self.browse_rsa_public).grid(row=2, column=2, padx=5, pady=5)
        
        # Private key file
        ttk.Label(rsa_frame, text="Private Key:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.rsa_private_var = tk.StringVar()
        ttk.Entry(rsa_frame, textvariable=self.rsa_private_var, width=50).grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(rsa_frame, text="Browse", command=self.browse_rsa_private).grid(row=3, column=2, padx=5, pady=5)
        
        # Private key password
        ttk.Label(rsa_frame, text="Key Password:").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.rsa_password_var = tk.StringVar()
        ttk.Entry(rsa_frame, textvariable=self.rsa_password_var, show='*', width=50).grid(row=4, column=1, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(rsa_frame)
        button_frame.grid(row=5, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Encrypt", command=self.rsa_encrypt).pack(side='left', padx=10)
        ttk.Button(button_frame, text="Decrypt", command=self.rsa_decrypt).pack(side='left', padx=10)
        
        # Result text
        self.rsa_result_text = scrolledtext.ScrolledText(rsa_frame, height=10, width=80)
        self.rsa_result_text.grid(row=6, column=0, columnspan=3, padx=5, pady=5)
    
    def create_keygen_tab(self, notebook):
        """Create key generation tab"""
        keygen_frame = ttk.Frame(notebook)
        notebook.add(keygen_frame, text="Key Generation")
        
        # RSA key generation
        ttk.Label(keygen_frame, text="RSA Key Generation", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=3, pady=10)
        
        # Key size
        ttk.Label(keygen_frame, text="Key Size:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.key_size_var = tk.StringVar(value="2048")
        key_size_combo = ttk.Combobox(keygen_frame, textvariable=self.key_size_var, values=["1024", "2048", "4096"])
        key_size_combo.grid(row=1, column=1, padx=5, pady=5)
        
        # Private key file
        ttk.Label(keygen_frame, text="Private Key File:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.gen_private_var = tk.StringVar()
        ttk.Entry(keygen_frame, textvariable=self.gen_private_var, width=50).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(keygen_frame, text="Browse", command=self.browse_gen_private).grid(row=2, column=2, padx=5, pady=5)
        
        # Public key file
        ttk.Label(keygen_frame, text="Public Key File:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.gen_public_var = tk.StringVar()
        ttk.Entry(keygen_frame, textvariable=self.gen_public_var, width=50).grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(keygen_frame, text="Browse", command=self.browse_gen_public).grid(row=3, column=2, padx=5, pady=5)
        
        # Key password
        ttk.Label(keygen_frame, text="Key Password (optional):").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.gen_password_var = tk.StringVar()
        ttk.Entry(keygen_frame, textvariable=self.gen_password_var, show='*', width=50).grid(row=4, column=1, padx=5, pady=5)
        
        # Generate button
        ttk.Button(keygen_frame, text="Generate Keys", command=self.generate_keys).grid(row=5, column=0, columnspan=3, pady=20)
        
        # Result text
        self.keygen_result_text = scrolledtext.ScrolledText(keygen_frame, height=15, width=80)
        self.keygen_result_text.grid(row=6, column=0, columnspan=3, padx=5, pady=5)
    
    # Browse methods
    def browse_aes_input(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.aes_input_var.set(filename)
    
    def browse_aes_output(self):
        filename = filedialog.asksaveasfilename()
        if filename:
            self.aes_output_var.set(filename)
    
    def browse_rsa_input(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.rsa_input_var.set(filename)
    
    def browse_rsa_output(self):
        filename = filedialog.asksaveasfilename()
        if filename:
            self.rsa_output_var.set(filename)
    
    def browse_rsa_public(self):
        filename = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if filename:
            self.rsa_public_var.set(filename)
    
    def browse_rsa_private(self):
        filename = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if filename:
            self.rsa_private_var.set(filename)
    
    def browse_gen_private(self):
        filename = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if filename:
            self.gen_private_var.set(filename)
    
    def browse_gen_public(self):
        filename = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if filename:
            self.gen_public_var.set(filename)
    
    # Encryption/Decryption methods
    def aes_encrypt(self):
        input_file = self.aes_input_var.get()
        output_file = self.aes_output_var.get()
        password = self.aes_password_var.get()
        
        if not all([input_file, output_file, password]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        success, message = self.encryption_tool.encrypt_file_aes(input_file, output_file, password)
        self.aes_result_text.insert(tk.END, f"{message}\n")
        
        if success:
            messagebox.showinfo("Success", "File encrypted successfully!")
        else:
            messagebox.showerror("Error", message)
    
    def aes_decrypt(self):
        input_file = self.aes_input_var.get()
        output_file = self.aes_output_var.get()
        password = self.aes_password_var.get()
        
        if not all([input_file, output_file, password]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        success, message = self.encryption_tool.decrypt_file_aes(input_file, output_file, password)
        self.aes_result_text.insert(tk.END, f"{message}\n")
        
        if success:
            messagebox.showinfo("Success", "File decrypted successfully!")
        else:
            messagebox.showerror("Error", message)
    
    def rsa_encrypt(self):
        input_file = self.rsa_input_var.get()
        output_file = self.rsa_output_var.get()
        public_key = self.rsa_public_var.get()
        
        if not all([input_file, output_file, public_key]):
            messagebox.showerror("Error", "Please fill all required fields")
            return
        
        success, message = self.encryption_tool.encrypt_file_rsa(input_file, output_file, public_key)
        self.rsa_result_text.insert(tk.END, f"{message}\n")
        
        if success:
            messagebox.showinfo("Success", "File encrypted successfully!")
        else:
            messagebox.showerror("Error", message)
    
    def rsa_decrypt(self):
        input_file = self.rsa_input_var.get()
        output_file = self.rsa_output_var.get()
        private_key = self.rsa_private_var.get()
        password = self.rsa_password_var.get() or None
        
        if not all([input_file, output_file, private_key]):
            messagebox.showerror("Error", "Please fill all required fields")
            return
        
        success, message = self.encryption_tool.decrypt_file_rsa(input_file, output_file, private_key, password)
        self.rsa_result_text.insert(tk.END, f"{message}\n")
        
        if success:
            messagebox.showinfo("Success", "File decrypted successfully!")
        else:
            messagebox.showerror("Error", message)
    
    def generate_keys(self):
        private_key_file = self.gen_private_var.get()
        public_key_file = self.gen_public_var.get()
        key_size = int(self.key_size_var.get())
        password = self.gen_password_var.get() or None
        
        if not all([private_key_file, public_key_file]):
            messagebox.showerror("Error", "Please specify key file paths")
            return
        
        try:
            self.keygen_result_text.insert(tk.END, "Generating RSA key pair...\n")
            private_key, public_key = self.encryption_tool.generate_rsa_keypair(key_size)
            
            success, message = self.encryption_tool.save_rsa_keys(
                private_key, public_key, private_key_file, public_key_file, password
            )
            
            self.keygen_result_text.insert(tk.END, f"{message}\n")
            
            if success:
                messagebox.showinfo("Success", "RSA key pair generated successfully!")
            else:
                messagebox.showerror("Error", message)
                
        except Exception as e:
            error_msg = f"Key generation failed: {str(e)}"
            self.keygen_result_text.insert(tk.END, f"{error_msg}\n")
            messagebox.showerror("Error", error_msg)
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

def main():
    # Check if GUI or CLI mode
    if len(sys.argv) > 1 and sys.argv[1] == '--cli':
        # CLI mode
        tool = AdvancedEncryptionTool()
        
        print("=== Advanced Encryption Tool (CLI) ===")
        print("1. AES File Encryption")
        print("2. AES File Decryption") 
        print("3. Generate RSA Keys")
        print("4. RSA File Encryption")
        print("5. RSA File Decryption")
        
        choice = input("Select option (1-5): ").strip()
        
        if choice == '1':
            input_file = input("Input file: ").strip()
            output_file = input("Output file: ").strip()
            password = input("Password: ").strip()
            success, message = tool.encrypt_file_aes(input_file, output_file, password)
            print(message)
        
        elif choice == '2':
            input_file = input("Input file: ").strip()
            output_file = input("Output file: ").strip()
            password = input("Password: ").strip()
            success, message = tool.decrypt_file_aes(input_file, output_file, password)
            print(message)
        
        elif choice == '3':
            private_file = input("Private key file: ").strip()
            public_file = input("Public key file: ").strip()
            password = input("Key password (optional): ").strip() or None
            
            private_key, public_key = tool.generate_rsa_keypair()
            success, message = tool.save_rsa_keys(private_key, public_key, private_file, public_file, password)
            print(message)
        
        # Add other CLI options...
        
    else:
        # GUI mode
        app = EncryptionGUI()
        app.run()

if __name__ == "__main__":
    main()
