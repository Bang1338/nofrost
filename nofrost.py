"""
File format (when decrypted):
- Magic: DE 00 1C E0 (4 bytes)
- Version: 1 (4 bytes) - This can be changed
- File count: N (4 bytes)
- File entries (N entries):
  - Filename: null-terminated string
  - Offset: 4 bytes
  - Size: 4 bytes
- File data
"""

import struct
import sys
import os
from Crypto.Cipher import Salsa20

DEBUG = 0

TIU_KEY = bytes([
    0x9a, 0x80, 0xac, 0x89, 0x1e, 0xe3, 0xe8, 0x80,
    0xcd, 0x0c, 0xa3, 0x8d, 0x45, 0x89, 0x07, 0x46,
    0xff, 0x41, 0x08, 0x4d, 0x8d, 0x0b, 0xb0, 0x0c,
    0x88, 0xf3, 0x89, 0xc0, 0x31, 0x88, 0xd9, 0xdc
])

TIU_IV_BASE = bytes([
    0xfa, 0x1c, 0x83, 0x3f, 0xb2, 0xe0, 0x31, 0xc4
])

# idk why Tape It Up using that shit
def gen_iv(file_size):
    modified_nonce = bytearray(8)
    for i in range(8):
        modified_nonce[i] = (TIU_IV_BASE[i] + file_size) & 0xFF
        
    print(f"Calculated IV: {bytes(modified_nonce).hex()}")
    return bytes(modified_nonce)

def decrypt_salsa20(data, file_size):
    iv = gen_iv(file_size)
    
    cipher = Salsa20.new(key=TIU_KEY, nonce=iv)
    return cipher.decrypt(data)

class NoFRoST:
    def __init__(self, filepath):
        self.filepath = filepath
        self.magic = None
        self.version = None
        self.file_count = None
        self.files = []
        
    def parse(self):
        with open(self.filepath, 'rb') as f:
            file_data = f.read()
            file_size = len(file_data)
            
            print(f"Original file size: {file_size} bytes")
            
            decrypted_data = decrypt_salsa20(file_data, file_size)
            
            self.magic = struct.unpack('<I', decrypted_data[0:4])[0]
            self.version = struct.unpack('<I', decrypted_data[4:8])[0] 
            self.file_count = struct.unpack('<I', decrypted_data[8:12])[0]
            
            print(f"Magic: 0x{self.magic:08X}")
            print(f"Version: {self.version}")
            print(f"File count: {self.file_count}")
            
            if self.magic != 0xE01C00DE:
                print(f"Magic number not found. Expected E01C00DE, got 0x{self.magic:08X}")
                return False
                
            if self.version != 1:
                print(f"Unsupported version. Expected 1, got {self.version}\nContinue anyway...")
                # return False
            
            decrypted_path = (self.filepath).replace(".pak","-decrypted.pak")
            with open(decrypted_path, 'wb') as file:
                file.write(decrypted_data)
                
            print(f"Decrypted .pak written to {decrypted_path}")
            
            offset = 12
            for i in range(self.file_count):
                filename_start = offset
                while decrypted_data[offset] != 0:
                    offset += 1
                filename = decrypted_data[filename_start:offset].decode('utf-8')
                offset += 1  # Skip null
                
                file_offset = struct.unpack('<I', decrypted_data[offset:offset+4])[0]
                offset += 4
                file_size = struct.unpack('<I', decrypted_data[offset:offset+4])[0]
                offset += 4
                
                self.files.append({
                    'filename': filename,
                    'offset': file_offset,
                    'size': file_size,
                    'data': decrypted_data[file_offset:file_offset+file_size]
                })
                
                if DEBUG: print(f"File {i+1}: {filename} (offset: 0x{file_offset:08X}, size: {file_size} bytes)")
            
            return True
    
    def extract_files(self, output_dir):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        for file_info in self.files:
            output_path = os.path.join(output_dir, file_info['filename'])
            
            # Create subdirectories if needed
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'wb') as f:
                f.write(file_info['data'])
            
            if DEBUG: print(f"Extracted: {output_path}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python nofrost.py <input_pak_file> <output_directory>")
        print("Example: python nofrost.py tape.pak extracted/")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    print(f"Parsing PAK file: {input_file}")
    nfr = NoFRoST(input_file)
    
    if nfr.parse():
        print(f"\nExtracting files to: {output_dir}")
        nfr.extract_files(output_dir)
        print(f"\nExtraction complete! {len(nfr.files)} files extracted.")
    else:
        print("Failed to parse PAK file.")
        sys.exit(1)

if __name__ == "__main__":
    main()
