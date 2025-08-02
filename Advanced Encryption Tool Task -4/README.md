# Advanced Encryption Tool

A powerful encryption tool with both GUI and CLI interfaces, supporting AES-256-GCM and RSA encryption for secure file protection.

## Features

### Encryption Methods
- **AES-256-GCM**
  - Password-based encryption
  - Secure key derivation (PBKDF2)
  - Authenticated encryption
  - File integrity protection

- **RSA Encryption**
  - Public/private key cryptography
  - Hybrid encryption (RSA + AES)
  - Customizable key sizes (1024/2048/4096 bits)
  - Protected private key storage

### User Interfaces
1. **Graphical User Interface (GUI)**
   - User-friendly tabbed interface
   - File browsing capabilities
   - Progress feedback
   - Error reporting
   - Key management tools

2. **Command Line Interface (CLI)**
   - Quick automation support
   - Script integration
   - Batch processing capability

## Requirements

- Python 3.x
- Required packages:
  ```bash
  pip install cryptography tkinter
  ```

## Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### GUI Mode
Run the tool without any arguments:
```bash
python main.py
```

The GUI provides three main tabs:
1. **AES Encryption**
   - Select input/output files
   - Enter encryption password
   - Choose encrypt/decrypt operation

2. **RSA Encryption**
   - Select input/output files
   - Choose public/private key files
   - Optional key password for private key
   - Encrypt/decrypt operations

3. **Key Generation**
   - Generate RSA key pairs
   - Choose key size
   - Set optional private key password
   - Save public/private keys

### CLI Mode
Run with --cli argument:
```bash
python main.py --cli
```

Available CLI options:
1. AES File Encryption
2. AES File Decryption
3. Generate RSA Keys
4. RSA File Encryption
5. RSA File Decryption

## Security Features

- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Encryption**: AES-256 in GCM mode
- **RSA**: Support for up to 4096-bit keys
- **Authentication**: GCM provides authenticated encryption
- **Salt**: Unique salt for each encryption
- **IV**: Random IV for each operation
- **Protected Keys**: Encrypted private key storage

## Best Practices

1. **Password Security**
   - Use strong, unique passwords
   - Consider using a password manager
   - Never reuse encryption passwords

2. **Key Management**
   - Keep private keys secure
   - Back up keys safely
   - Use password protection for private keys
   - Never share private keys

3. **File Handling**
   - Keep original files backed up
   - Verify decryption success
   - Use secure deletion for sensitive files

## Error Handling

The tool provides comprehensive error handling for:
- File access issues
- Invalid passwords
- Corrupted files
- Key format problems
- Permission errors
- Memory constraints

## Technical Details

### AES Implementation
- Mode: GCM (Galois/Counter Mode)
- Key Size: 256 bits
- Authentication: Built-in with GCM
- Chunk Size: 8192 bytes

### RSA Implementation
- Padding: OAEP with SHA-256
- Key Sizes: 1024, 2048, or 4096 bits
- Format: PKCS#8 (private), SubjectPublicKeyInfo (public)
- Hybrid: RSA for key exchange, AES for data

## License

This project is for educational and personal use. Use responsibly and in compliance with local laws and regulations.

## Warning

This tool is designed for legitimate file encryption. Users are responsible for:
- Compliance with local laws
- Safe key/password management
- Backup of important files
- Ethical use of encryption

## Contributing

Contributions are welcome! Please ensure:
1. Code follows security best practices
2. Comprehensive error handling
3. Documentation of changes
4. Test coverage for new features
