use std::fs;
use std::path::Path;
use std::io::{self, Read};
use sha2::{Sha256, Digest};
use md5;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
struct FileMetadata {
    path: String,
    name: String,
    size: u64,
    created: Option<String>,
    modified: Option<String>,
    accessed: Option<String>,
    is_directory: bool,
    permissions: String,
    file_type: String,
    md5_hash: Option<String>,
    sha256_hash: Option<String>,
    magic_bytes: Option<String>,
}

struct FileSystemAnalyzer {
    file_signatures: HashMap<Vec<u8>, &'static str>,
}

impl FileSystemAnalyzer {
    fn new() -> Self {
        let mut signatures = HashMap::new();
        signatures.insert(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], "PNG");
        signatures.insert(vec![0xFF, 0xD8, 0xFF], "JPEG");
        signatures.insert(vec![0x47, 0x49, 0x46, 0x38, 0x37, 0x61], "GIF87a");
        signatures.insert(vec![0x47, 0x49, 0x46, 0x38, 0x39, 0x61], "GIF89a");
        signatures.insert(vec![0x25, 0x50, 0x44, 0x46], "PDF");
        signatures.insert(vec![0x50, 0x4B, 0x03, 0x04], "ZIP");
        signatures.insert(vec![0x4D, 0x5A], "PE Executable");
        signatures.insert(vec![0x7F, 0x45, 0x4C, 0x46], "ELF");
        signatures.insert(vec![0xD0, 0xCF, 0x11, 0xE0], "MS Office");
        
        FileSystemAnalyzer {
            file_signatures: signatures,
        }
    }

    fn identify_file_type(&self, file_path: &Path) -> String {
        if let Ok(mut file) = fs::File::open(file_path) {
            let mut buffer = vec![0; 32];
            if let Ok(_) = file.read(&mut buffer) {
                for (signature, file_type) in &self.file_signatures {
                    if buffer.starts_with(signature) {
                        return file_type.to_string();
                    }
                }
            }
        }
        "Unknown".to_string()
    }

    fn calculate_hashes(&self, file_path: &Path) -> (Option<String>, Option<String>) {
        if let Ok(content) = fs::read(file_path) {
            let md5_hash = format!("{:x}", md5::compute(&content));
            let sha256_hash = format!("{:x}", Sha256::digest(&content));
            (Some(md5_hash), Some(sha256_hash))
        } else {
            (None, None)
        }
    }

    fn get_magic_bytes(&self, file_path: &Path) -> Option<String> {
        if let Ok(mut file) = fs::File::open(file_path) {
            let mut buffer = vec![0; 16];
            if let Ok(bytes_read) = file.read(&mut buffer) {
                buffer.truncate(bytes_read);
                return Some(buffer.iter().map(|b| format!("{:02x}", b)).collect::<String>());
            }
        }
        None
    }

    fn analyze_file(&self, file_path: &Path) -> io::Result<FileMetadata> {
        let metadata = fs::metadata(file_path)?;
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        let created = metadata.created().ok()
            .and_then(|t| DateTime::<Utc>::from(t).format("%Y-%m-%d %H:%M:%S UTC").to_string().into());
        
        let modified = metadata.modified().ok()
            .and_then(|t| DateTime::<Utc>::from(t).format("%Y-%m-%d %H:%M:%S UTC").to_string().into());

        let accessed = metadata.accessed().ok()
            .and_then(|t| DateTime::<Utc>::from(t).format("%Y-%m-%d %H:%M:%S UTC").to_string().into());

        let (md5_hash, sha256_hash) = if metadata.is_file() {
            self.calculate_hashes(file_path)
        } else {
            (None, None)
        };

        let file_type = if metadata.is_file() {
            self.identify_file_type(file_path)
        } else {
            "Directory".to_string()
        };

        let magic_bytes = if metadata.is_file() {
            self.get_magic_bytes(file_path)
        } else {
            None
        };

        Ok(FileMetadata {
            path: file_path.to_string_lossy().to_string(),
            name: file_name,
            size: metadata.len(),
            created,
            modified,
            accessed,
            is_directory: metadata.is_dir(),
            permissions: format!("{:o}", metadata.permissions().mode()),
            file_type,
            md5_hash,
            sha256_hash,
            magic_bytes,
        })
    }

    fn scan_directory(&self, dir_path: &Path, recursive: bool) -> io::Result<Vec<FileMetadata>> {
        let mut results = Vec::new();
        
        fn scan_recursive(
            analyzer: &FileSystemAnalyzer, 
            dir: &Path, 
            recursive: bool, 
            results: &mut Vec<FileMetadata>
        ) -> io::Result<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                
                match analyzer.analyze_file(&path) {
                    Ok(metadata) => results.push(metadata),
                    Err(e) => eprintln!("Error analyzing {}: {}", path.display(), e),
                }

                if recursive && path.is_dir() {
                    scan_recursive(analyzer, &path, recursive, results)?;
                }
            }
            Ok(())
        }

        scan_recursive(self, dir_path, recursive, &mut results)?;
        Ok(results)
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <path> [recursive] [output.json]", args[0]);
        std::process::exit(1);
    }

    let path = Path::new(&args[1]);
    let recursive = args.get(2).map_or(false, |s| s == "true");
    let output_file = args.get(3);

    let analyzer = FileSystemAnalyzer::new();
    
    let results = if path.is_dir() {
        analyzer.scan_directory(path, recursive)?
    } else {
        vec![analyzer.analyze_file(path)?]
    };

    let json_output = serde_json::to_string_pretty(&results)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    if let Some(output_path) = output_file {
        fs::write(output_path, json_output)?;
        println!("Results saved to {}", output_path);
    } else {
        println!("{}", json_output);
    }

    Ok(())
}
