package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// FileInfo represents file metadata for forensic analysis
type FileInfo struct {
	Path         string            `json:"path"`
	Name         string            `json:"name"`
	Size         int64             `json:"size"`
	Mode         string            `json:"mode"`
	ModTime      time.Time         `json:"mod_time"`
	IsDir        bool              `json:"is_dir"`
	Hashes       map[string]string `json:"hashes"`
	MagicBytes   string            `json:"magic_bytes"`
	Extension    string            `json:"extension"`
	Permissions  string            `json:"permissions"`
}

// FileCarver performs file carving operations
type FileCarver struct {
	outputDir string
}

// NewFileCarver creates a new file carver instance
func NewFileCarver(outputDir string) *FileCarver {
	return &FileCarver{outputDir: outputDir}
}

// calculateHashes computes MD5, SHA1, and SHA256 hashes
func calculateHashes(filePath string) (map[string]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)
	
	if _, err := io.Copy(multiWriter, file); err != nil {
		return nil, err
	}

	hashes := map[string]string{
		"md5":    hex.EncodeToString(md5Hash.Sum(nil)),
		"sha1":   hex.EncodeToString(sha1Hash.Sum(nil)),
		"sha256": hex.EncodeToString(sha256Hash.Sum(nil)),
	}

	return hashes, nil
}

// getMagicBytes reads the first 16 bytes of a file
func getMagicBytes(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buffer := make([]byte, 16)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return "", err
	}

	return hex.EncodeToString(buffer[:n]), nil
}

// analyzeFile extracts comprehensive metadata from a file
func analyzeFile(filePath string) (*FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	var hashes map[string]string
	var magicBytes string

	if !info.IsDir() {
		hashes, _ = calculateHashes(filePath)
		magicBytes, _ = getMagicBytes(filePath)
	}

	fileInfo := &FileInfo{
		Path:        filePath,
		Name:        info.Name(),
		Size:        info.Size(),
		Mode:        info.Mode().String(),
		ModTime:     info.ModTime(),
		IsDir:       info.IsDir(),
		Hashes:      hashes,
		MagicBytes:  magicBytes,
		Extension:   filepath.Ext(filePath),
		Permissions: info.Mode().Perm().String(),
	}

	return fileInfo, nil
}

// scanDirectory recursively scans a directory and analyzes all files
func scanDirectory(dirPath string, recursive bool) ([]*FileInfo, error) {
	var results []*FileInfo

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip subdirectories if not recursive
		if !recursive && info.IsDir() && path != dirPath {
			return filepath.SkipDir
		}

		fileInfo, err := analyzeFile(path)
		if err != nil {
			log.Printf("Error analyzing %s: %v", path, err)
			return nil
		}

		results = append(results, fileInfo)
		return nil
	})

	return results, err
}

// findDeletedFiles searches for deleted file signatures in unallocated space
func (fc *FileCarver) findDeletedFiles(imagePath string) error {
	// This is a simplified implementation
	// In practice, you'd need to parse the file system structure
	file, err := os.Open(imagePath)
	if err != nil {
		return err
	}
	defer file.Close()

	buffer := make([]byte, 4096)
	fileSignatures := map[string]string{
		"ffd8ff":   "jpg",
		"89504e47": "png",
		"47494638": "gif",
		"25504446": "pdf",
		"504b0304": "zip",
	}

	offset := int64(0)
	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		hexData := hex.EncodeToString(buffer[:n])
		
		for signature, extension := range fileSignatures {
			if len(hexData) >= len(signature) {
				for i := 0; i <= len(hexData)-len(signature); i++ {
					if hexData[i:i+len(signature)] == signature {
						fmt.Printf("Found %s signature at offset %d\n", extension, offset+int64(i/2))
						// Here you would extract the file
					}
				}
			}
		}

		offset += int64(n)
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run file_analyzer.go <path> [recursive] [output.json]")
		return
	}

	path := os.Args[1]
	recursive := len(os.Args) > 2 && os.Args[2] == "true"
	outputFile := ""
	if len(os.Args) > 3 {
		outputFile = os.Args[3]
	}

	var results []*FileInfo
	var err error

	info, err := os.Stat(path)
	if err != nil {
		log.Fatal(err)
	}

	if info.IsDir() {
		results, err = scanDirectory(path, recursive)
	} else {
		fileInfo, err := analyzeFile(path)
		if err != nil {
			log.Fatal(err)
		}
		results = []*FileInfo{fileInfo}
	}

	if err != nil {
		log.Fatal(err)
	}

	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(results); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Results saved to %s\n", outputFile)
	} else {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		encoder.Encode(results)
	}
}
