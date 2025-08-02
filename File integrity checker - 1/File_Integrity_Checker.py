import hashlib
import os
import json
import time
from datetime import datetime

class FileIntegrityChecker:
    def __init__(self, database_file="file_hashes.json"):
        self.database_file = database_file
        self.hash_database = self.load_database()
    
    def load_database(self):
        """Load existing hash database or create new one"""
        try:
            with open(self.database_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def save_database(self):
        """Save hash database to file"""
        with open(self.database_file, 'w') as f:
            json.dump(self.hash_database, f, indent=2)
    
    def calculate_file_hash(self, filepath, algorithm='sha256'):
        """Calculate hash of a file"""
        hash_algo = hashlib.new(algorithm)
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_algo.update(chunk)
            return hash_algo.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {filepath}: {e}")
            return None
    
    def add_file(self, filepath):
        """Add file to monitoring database"""
        if os.path.exists(filepath):
            file_hash = self.calculate_file_hash(filepath)
            if file_hash:
                self.hash_database[filepath] = {
                    'hash': file_hash,
                    'last_modified': os.path.getmtime(filepath),
                    'added_date': datetime.now().isoformat()
                }
                self.save_database()
                print(f"Added {filepath} to monitoring")
            else:
                print(f"Failed to calculate hash for {filepath}")
        else:
            print(f"File {filepath} does not exist")
    
    def check_file_integrity(self, filepath):
        """Check if file has been modified"""
        if filepath not in self.hash_database:
            print(f"File {filepath} not in database. Add it first.")
            return False
        
        current_hash = self.calculate_file_hash(filepath)
        stored_hash = self.hash_database[filepath]['hash']
        
        if current_hash == stored_hash:
            print(f"✓ {filepath} - INTEGRITY INTACT")
            return True
        else:
            print(f"✗ {filepath} - FILE MODIFIED!")
            print(f"  Stored hash:  {stored_hash}")
            print(f"  Current hash: {current_hash}")
            return False
    
    def monitor_all_files(self):
        """Check integrity of all monitored files"""
        print("=== File Integrity Check Report ===")
        print(f"Timestamp: {datetime.now()}")
        print("-" * 40)
        
        modified_files = []
        for filepath in self.hash_database:
            if os.path.exists(filepath):
                if not self.check_file_integrity(filepath):
                    modified_files.append(filepath)
            else:
                print(f"✗ {filepath} - FILE NOT FOUND!")
                modified_files.append(filepath)
        
        print("-" * 40)
        if modified_files:
            print(f"WARNING: {len(modified_files)} file(s) modified or missing!")
        else:
            print("All monitored files are intact.")
        
        return modified_files
    
    def remove_file(self, filepath):
        """Remove file from monitoring"""
        if filepath in self.hash_database:
            del self.hash_database[filepath]
            self.save_database()
            print(f"Removed {filepath} from monitoring")
        else:
            print(f"File {filepath} not in database")
    
    def list_monitored_files(self):
        """List all monitored files"""
        print("=== Monitored Files ===")
        for filepath, data in self.hash_database.items():
            print(f"File: {filepath}")
            print(f"  Hash: {data['hash'][:16]}...")
            print(f"  Added: {data['added_date']}")
            print()

def main():
    print("Starting File Integrity Checker...")
    checker = FileIntegrityChecker()
    print("Database loaded successfully!")
    
    while True:
        print("\n=== File Integrity Checker ===")
        print("1. Add file to monitoring")
        print("2. Check specific file")
        print("3. Check all monitored files")
        print("4. List monitored files")
        print("5. Remove file from monitoring")
        print("6. Exit")
        
        choice = input("Enter your choice (1-6): ").strip()
        
        if choice == '1':
            filepath = input("Enter file path: ").strip()
            checker.add_file(filepath)
        
        elif choice == '2':
            filepath = input("Enter file path: ").strip()
            checker.check_file_integrity(filepath)
        
        elif choice == '3':
            checker.monitor_all_files()
        
        elif choice == '4':
            checker.list_monitored_files()
        
        elif choice == '5':
            filepath = input("Enter file path to remove: ").strip()
            checker.remove_file(filepath)
        
        elif choice == '6':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
