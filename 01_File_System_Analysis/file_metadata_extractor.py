#!/usr/bin/env python3
"""
File Metadata Extractor
Extracts comprehensive metadata from files including timestamps, permissions, and file signatures
"""

import os
import stat
import time
import hashlib
import argparse
from pathlib import Path
import json

class FileMetadataExtractor:
    def __init__(self):
        self.file_signatures = {
            b'\x89PNG\r\n\x1a\n': 'PNG Image',
            b'\xff\xd8\xff': 'JPEG Image',
            b'GIF87a': 'GIF Image (87a)',
            b'GIF89a': 'GIF Image (89a)',
            b'%PDF': 'PDF Document',
            b'PK\x03\x04': 'ZIP Archive',
            b'PK\x05\x06': 'ZIP Archive (empty)',
            b'PK\x07\x08': 'ZIP Archive (spanned)',
            b'\x50\x4b\x03\x04': 'ZIP/Office Document',
            b'MZ': 'Windows Executable',
            b'\x7fELF': 'Linux Executable',
            b'\xd0\xcf\x11\xe0': 'MS Office Document (Legacy)',
            b'RIFF': 'RIFF Container (AVI/WAV)',
            b'\x00\x00\x01\x00': 'ICO Image',
            b'BM': 'Bitmap Image'
        }
    
    def get_file_signature(self, file_path):
        """Identify file type by magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)
                for signature, file_type in self.file_signatures.items():
                    if header.startswith(signature):
                        return file_type
                return 'Unknown'
        except Exception:
            return 'Error reading file'
    
    def calculate_hashes(self, file_path):
        """Calculate MD5, SHA1, and SHA256 hashes"""
        hashes = {'md5': '', 'sha1': '', 'sha256': ''}
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
        except Exception as e:
            hashes['error'] = str(e)
        return hashes
    
    def extract_metadata(self, file_path):
        """Extract comprehensive file metadata"""
        try:
            file_stat = os.stat(file_path)
            metadata = {
                'file_path': str(file_path),
                'file_name': os.path.basename(file_path),
                'file_size': file_stat.st_size,
                'file_signature': self.get_file_signature(file_path),
                'timestamps': {
                    'created': time.ctime(file_stat.st_ctime),
                    'modified': time.ctime(file_stat.st_mtime),
                    'accessed': time.ctime(file_stat.st_atime),
                    'created_timestamp': file_stat.st_ctime,
                    'modified_timestamp': file_stat.st_mtime,
                    'accessed_timestamp': file_stat.st_atime
                },
                'permissions': {
                    'mode': oct(file_stat.st_mode),
                    'readable': os.access(file_path, os.R_OK),
                    'writable': os.access(file_path, os.W_OK),
                    'executable': os.access(file_path, os.X_OK)
                },
                'ownership': {
                    'uid': file_stat.st_uid,
                    'gid': file_stat.st_gid
                },
                'hashes': self.calculate_hashes(file_path)
            }
            return metadata
        except Exception as e:
            return {'error': str(e), 'file_path': str(file_path)}
    
    def analyze_directory(self, directory_path, recursive=True):
        """Analyze all files in a directory"""
        results = []
        path = Path(directory_path)
        
        if recursive:
            files = path.rglob('*')
        else:
            files = path.glob('*')
        
        for file_path in files:
            if file_path.is_file():
                metadata = self.extract_metadata(file_path)
                results.append(metadata)
        
        return results

def main():
    parser = argparse.ArgumentParser(description='Extract file metadata for forensic analysis')
    parser.add_argument('path', help='File or directory path to analyze')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursive directory analysis')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    extractor = FileMetadataExtractor()
    
    if os.path.isfile(args.path):
        results = [extractor.extract_metadata(args.path)]
    elif os.path.isdir(args.path):
        results = extractor.analyze_directory(args.path, args.recursive)
    else:
        print(f"Error: {args.path} is not a valid file or directory")
        return
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))

if __name__ == '__main__':
    main()
