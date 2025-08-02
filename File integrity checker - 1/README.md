# File Integrity Checker

A Python-based tool for monitoring and verifying the integrity of files in your system. This tool helps detect unauthorized modifications, corruptions, or tampering of files by maintaining and checking cryptographic hashes.

## Features

- **File Monitoring**
  - Add files to monitoring database
  - SHA-256 hash calculation
  - Timestamp tracking
  - Modification detection

- **Integrity Verification**
  - Individual file checking
  - Bulk verification of all monitored files
  - Detailed integrity reports
  - Quick hash comparison

- **File Management**
  - List all monitored files
  - Add/Remove files from monitoring
  - Persistent storage of file hashes
  - JSON-based database

## How It Works

1. When a file is added to monitoring:
   - Calculates SHA-256 hash of the file
   - Stores hash, timestamp, and metadata
   - Saves information to database

2. During integrity checks:
   - Recalculates current file hash
   - Compares with stored hash
   - Reports any modifications
   - Identifies missing files

## Requirements

- Python 3.x
- Standard library modules:
  - hashlib
  - json
  - os
  - datetime

## Installation

1. Clone or download this repository
2. No additional packages required (uses Python standard library)

## Usage

Run the script:
```bash
python File_Integrity_Checker.py
```

### Menu Options

1. **Add file to monitoring**
   - Add new files to the integrity checker
   - Stores initial hash and metadata

2. **Check specific file**
   - Verify integrity of a single file
   - Shows comparison of stored vs current hash

3. **Check all monitored files**
   - Bulk integrity check of all files
   - Generates comprehensive report

4. **List monitored files**
   - View all files in database
   - Display hash snippets and add dates

5. **Remove file from monitoring**
   - Delete file from monitoring database
   - Clean up unused entries

6. **Exit**
   - Safely exit the program

## Database

- File hashes and metadata stored in `file_hashes.json`
- Format:
```json
{
  "filepath": {
    "hash": "sha256_hash_value",
    "last_modified": "timestamp",
    "added_date": "iso_date"
  }
}
```

## Use Cases

- System file integrity monitoring
- Security auditing
- Change detection
- File corruption detection
- Compliance verification

## Best Practices

1. Regularly check file integrity
2. Keep the hash database secure
3. Monitor critical system files
4. Verify files after system updates
5. Back up the hash database

## License

This project is available for educational and security monitoring purposes. Use responsibly.
