package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/traefik/traefik/v3/pkg/provider/acme"
	"github.com/traefik/traefik/v3/pkg/types"
)

// Test helper functions

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(notBefore, notAfter time.Time) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Return PEM encoded certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, nil
}

// mustGenerateTestCertificate creates a test certificate or fails the test
func mustGenerateTestCertificate(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	cert, err := generateTestCertificate(notBefore, notAfter)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}
	return cert
}

// createTestACMEFile creates a test ACME storage file
func createTestACMEFile(t *testing.T, filename string, data map[string]*acme.StoredData) {
	t.Helper()
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
}

// Test functions

func TestDefaultWorkers(t *testing.T) {
	workers := defaultWorkers()
	expected := runtime.GOMAXPROCS(0)
	if workers != expected {
		t.Errorf("defaultWorkers() = %d, want %d", workers, expected)
	}
	if workers < 1 {
		t.Errorf("defaultWorkers() = %d, should be at least 1", workers)
	}
}

func TestFormatDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   types.Domain
		expected string
	}{
		{
			name:     "empty domain",
			domain:   types.Domain{Main: ""},
			expected: "unknown",
		},
		{
			name:     "domain without SANs",
			domain:   types.Domain{Main: "example.com"},
			expected: "example.com",
		},
		{
			name: "domain with SANs",
			domain: types.Domain{
				Main: "example.com",
				SANs: []string{"www.example.com", "api.example.com"},
			},
			expected: "example.com (SANs: [www.example.com api.example.com])",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("formatDomain() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name        string
		cert        acme.Certificate
		checkTime   time.Time
		wantExpired bool
		wantErr     bool
	}{
		{
			name: "valid certificate",
			cert: acme.Certificate{
				Certificate: mustGenerateTestCertificate(t, now.Add(-24*time.Hour), now.Add(24*time.Hour)),
			},
			checkTime:   now,
			wantExpired: false,
			wantErr:     false,
		},
		{
			name: "expired certificate",
			cert: acme.Certificate{
				Certificate: mustGenerateTestCertificate(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour)),
			},
			checkTime:   now,
			wantExpired: true,
			wantErr:     false,
		},
		{
			name: "valid DER certificate",
			cert: acme.Certificate{
				Certificate: func() []byte {
					pemCert := mustGenerateTestCertificate(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))
					block, _ := pem.Decode(pemCert)
					if block == nil {
						t.Fatal("Failed to decode PEM certificate for DER test")
					}
					return block.Bytes // Return raw DER bytes
				}(),
			},
			checkTime:   now,
			wantExpired: false,
			wantErr:     false,
		},
		{
			name: "expired DER certificate",
			cert: acme.Certificate{
				Certificate: func() []byte {
					pemCert := mustGenerateTestCertificate(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
					block, _ := pem.Decode(pemCert)
					if block == nil {
						t.Fatal("Failed to decode PEM certificate for DER test")
					}
					return block.Bytes // Return raw DER bytes
				}(),
			},
			checkTime:   now,
			wantExpired: true,
			wantErr:     false,
		},
		{
			name: "empty certificate",
			cert: acme.Certificate{
				Certificate: []byte{},
			},
			checkTime:   now,
			wantExpired: true,
			wantErr:     true,
		},
		{
			name: "invalid certificate data",
			cert: acme.Certificate{
				Certificate: []byte("invalid certificate data"),
			},
			checkTime:   now,
			wantExpired: true,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expired, err := isExpired(tt.cert, tt.checkTime)
			if (err != nil) != tt.wantErr {
				t.Errorf("isExpired() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if expired != tt.wantExpired {
				t.Errorf("isExpired() = %v, want %v", expired, tt.wantExpired)
			}
		})
	}
}

func TestProcessFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir := t.TempDir()
	now := time.Now()

	tests := []struct {
		name              string
		setupFile         func(string) string
		expectedErr       bool
		expectedExpired   int
		expectedRemaining int
	}{
		{
			name: "file with expired certificates",
			setupFile: func(dir string) string {
				filename := filepath.Join(dir, "acme-expired.json")
				expiredCert := mustGenerateTestCertificate(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
				validCert := mustGenerateTestCertificate(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))

				data := map[string]*acme.StoredData{
					"default": {
						Certificates: []*acme.CertAndStore{
							{
								Certificate: acme.Certificate{
									Certificate: expiredCert,
									Domain:      types.Domain{Main: "expired.example.com"},
								},
							},
							{
								Certificate: acme.Certificate{
									Certificate: validCert,
									Domain:      types.Domain{Main: "valid.example.com"},
								},
							},
						},
					},
				}
				createTestACMEFile(t, filename, data)
				return filename
			},
			expectedErr:       false,
			expectedExpired:   1,
			expectedRemaining: 1,
		},
		{
			name: "file with no expired certificates",
			setupFile: func(dir string) string {
				filename := filepath.Join(dir, "acme-valid.json")
				validCert1 := mustGenerateTestCertificate(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))
				validCert2 := mustGenerateTestCertificate(t, now.Add(-12*time.Hour), now.Add(48*time.Hour))

				data := map[string]*acme.StoredData{
					"default": {
						Certificates: []*acme.CertAndStore{
							{
								Certificate: acme.Certificate{
									Certificate: validCert1,
									Domain:      types.Domain{Main: "valid1.example.com"},
								},
							},
							{
								Certificate: acme.Certificate{
									Certificate: validCert2,
									Domain:      types.Domain{Main: "valid2.example.com"},
								},
							},
						},
					},
				}
				createTestACMEFile(t, filename, data)
				return filename
			},
			expectedErr:       false,
			expectedExpired:   0,
			expectedRemaining: 2,
		},
		{
			name: "file with all expired certificates",
			setupFile: func(dir string) string {
				filename := filepath.Join(dir, "acme-all-expired.json")
				expiredCert1 := mustGenerateTestCertificate(t, now.Add(-72*time.Hour), now.Add(-48*time.Hour))
				expiredCert2 := mustGenerateTestCertificate(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

				data := map[string]*acme.StoredData{
					"default": {
						Certificates: []*acme.CertAndStore{
							{
								Certificate: acme.Certificate{
									Certificate: expiredCert1,
									Domain:      types.Domain{Main: "expired1.example.com"},
								},
							},
							{
								Certificate: acme.Certificate{
									Certificate: expiredCert2,
									Domain:      types.Domain{Main: "expired2.example.com"},
								},
							},
						},
					},
				}
				createTestACMEFile(t, filename, data)
				return filename
			},
			expectedErr:       false,
			expectedExpired:   2,
			expectedRemaining: 0,
		},
		{
			name: "empty ACME file",
			setupFile: func(dir string) string {
				filename := filepath.Join(dir, "acme-empty.json")
				data := map[string]*acme.StoredData{}
				createTestACMEFile(t, filename, data)
				return filename
			},
			expectedErr:       false,
			expectedExpired:   0,
			expectedRemaining: 0,
		},
		{
			name: "completely empty file (zero bytes)",
			setupFile: func(dir string) string {
				filename := filepath.Join(dir, "acme-zero-bytes.json")
				// Create a file with zero bytes (not even empty JSON)
				if err := os.WriteFile(filename, []byte{}, 0644); err != nil {
					t.Fatalf("Failed to write zero-byte file: %v", err)
				}
				return filename
			},
			expectedErr:       false,
			expectedExpired:   0,
			expectedRemaining: 0,
		},
		{
			name: "non-existent file",
			setupFile: func(dir string) string {
				return filepath.Join(dir, "non-existent.json")
			},
			expectedErr:       true,
			expectedExpired:   0,
			expectedRemaining: 0,
		},
		{
			name: "invalid JSON file",
			setupFile: func(dir string) string {
				filename := filepath.Join(dir, "invalid.json")
				if err := os.WriteFile(filename, []byte("invalid json content"), 0644); err != nil {
					t.Fatalf("Failed to write invalid JSON file: %v", err)
				}
				return filename
			},
			expectedErr:       true,
			expectedExpired:   0,
			expectedRemaining: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := tt.setupFile(tempDir)
			result := processFile(filename)

			if (result.err != nil) != tt.expectedErr {
				t.Errorf("processFile() error = %v, wantErr %v", result.err, tt.expectedErr)
			}
			if result.expiredCerts != tt.expectedExpired {
				t.Errorf("processFile() expiredCerts = %d, want %d", result.expiredCerts, tt.expectedExpired)
			}
			if result.remainingCerts != tt.expectedRemaining {
				t.Errorf("processFile() remainingCerts = %d, want %d", result.remainingCerts, tt.expectedRemaining)
			}

			// Verify the file was modified correctly if expired certs were removed
			if !tt.expectedErr && tt.expectedExpired > 0 {
				data, err := os.ReadFile(filename)
				if err != nil {
					t.Fatalf("Failed to read modified file: %v", err)
				}
				var storageData map[string]*acme.StoredData
				if err := json.Unmarshal(data, &storageData); err != nil {
					t.Fatalf("Failed to parse modified file: %v", err)
				}
				totalCerts := 0
				for _, storedData := range storageData {
					if storedData != nil && storedData.Certificates != nil {
						totalCerts += len(storedData.Certificates)
					}
				}
				if totalCerts != tt.expectedRemaining {
					t.Errorf("Modified file has %d certificates, want %d", totalCerts, tt.expectedRemaining)
				}
			}
		})
	}
}

func TestProcessFiles(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name            string
		workers         int
		expectedResults int
	}{
		{
			name:            "process multiple files with single worker",
			workers:         1,
			expectedResults: 2,
		},
		{
			name:            "process multiple files with multiple workers",
			workers:         2,
			expectedResults: 2,
		},
		{
			name:            "process single file",
			workers:         1,
			expectedResults: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh test files for each subtest to avoid race conditions
			tempDir := t.TempDir()

			// Create test file 1 with valid cert
			file1 := filepath.Join(tempDir, "acme1.json")
			validCert1 := mustGenerateTestCertificate(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))
			data1 := map[string]*acme.StoredData{
				"default": {
					Certificates: []*acme.CertAndStore{
						{
							Certificate: acme.Certificate{
								Certificate: validCert1,
								Domain:      types.Domain{Main: "valid1.example.com"},
							},
						},
					},
				},
			}
			createTestACMEFile(t, file1, data1)

			// For tests processing multiple files, create file2 with expired cert
			var files []string
			if tt.expectedResults == 2 {
				files = []string{file1}
				file2 := filepath.Join(tempDir, "acme2.json")
				expiredCert2 := mustGenerateTestCertificate(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
				data2 := map[string]*acme.StoredData{
					"default": {
						Certificates: []*acme.CertAndStore{
							{
								Certificate: acme.Certificate{
									Certificate: expiredCert2,
									Domain:      types.Domain{Main: "expired2.example.com"},
								},
							},
						},
					},
				}
				createTestACMEFile(t, file2, data2)
				files = append(files, file2)
			} else {
				files = []string{file1}
			}

			results := processFiles(files, tt.workers)
			if len(results) != tt.expectedResults {
				t.Errorf("processFiles() returned %d results, want %d", len(results), tt.expectedResults)
			}

			// Verify each result corresponds to an input file
			fileSet := make(map[string]bool)
			for _, file := range files {
				fileSet[file] = true
			}

			for _, result := range results {
				if !fileSet[result.filename] {
					t.Errorf("processFiles() returned result for unexpected file %s", result.filename)
				}
				// Verify no errors for our test files
				if result.err != nil {
					t.Errorf("processFiles() result for %s has unexpected error: %v", result.filename, result.err)
				}
			}

			// Verify expected counts for known files
			for _, result := range results {
				if result.filename == file1 {
					// file1 has 1 valid cert, should be 0 expired, 1 remaining
					if result.expiredCerts != 0 {
						t.Errorf("file1 result: expiredCerts = %d, want 0", result.expiredCerts)
					}
					if result.remainingCerts != 1 {
						t.Errorf("file1 result: remainingCerts = %d, want 1", result.remainingCerts)
					}
				} else if strings.Contains(result.filename, "acme2.json") {
					// file2 has 1 expired cert, should be 1 expired, 0 remaining
					if result.expiredCerts != 1 {
						t.Errorf("file2 result: expiredCerts = %d, want 1", result.expiredCerts)
					}
					if result.remainingCerts != 0 {
						t.Errorf("file2 result: remainingCerts = %d, want 0", result.remainingCerts)
					}
				}
			}
		})
	}
}

func TestProcessFilePreservesPermissions(t *testing.T) {
	// Skip this test on Windows where Unix permissions don't apply
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix permission test on Windows")
	}

	tempDir := t.TempDir()
	now := time.Now()

	filename := filepath.Join(tempDir, "acme-perms.json")
	expiredCert := mustGenerateTestCertificate(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	data := map[string]*acme.StoredData{
		"default": {
			Certificates: []*acme.CertAndStore{
				{
					Certificate: acme.Certificate{
						Certificate: expiredCert,
						Domain:      types.Domain{Main: "expired.example.com"},
					},
				},
			},
		},
	}
	createTestACMEFile(t, filename, data)

	// Set specific permissions
	originalPerm := os.FileMode(0600)
	if err := os.Chmod(filename, originalPerm); err != nil {
		t.Fatalf("Failed to set file permissions: %v", err)
	}

	// Process the file
	result := processFile(filename)
	if result.err != nil {
		t.Fatalf("processFile() error = %v", result.err)
	}

	// Verify permissions are preserved
	fileInfo, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	if fileInfo.Mode().Perm() != originalPerm {
		t.Errorf("File permissions changed from %o to %o", originalPerm, fileInfo.Mode().Perm())
	}
}

func TestProcessFileWithMultipleResolvers(t *testing.T) {
	tempDir := t.TempDir()
	now := time.Now()

	filename := filepath.Join(tempDir, "acme-multi-resolver.json")
	expiredCert := mustGenerateTestCertificate(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	validCert := mustGenerateTestCertificate(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))

	data := map[string]*acme.StoredData{
		"resolver1": {
			Certificates: []*acme.CertAndStore{
				{
					Certificate: acme.Certificate{
						Certificate: expiredCert,
						Domain:      types.Domain{Main: "expired.example.com"},
					},
				},
			},
		},
		"resolver2": {
			Certificates: []*acme.CertAndStore{
				{
					Certificate: acme.Certificate{
						Certificate: validCert,
						Domain:      types.Domain{Main: "valid.example.com"},
					},
				},
			},
		},
	}
	createTestACMEFile(t, filename, data)

	result := processFile(filename)
	if result.err != nil {
		t.Fatalf("processFile() error = %v", result.err)
	}

	if result.totalCerts != 2 {
		t.Errorf("processFile() totalCerts = %d, want 2", result.totalCerts)
	}
	if result.expiredCerts != 1 {
		t.Errorf("processFile() expiredCerts = %d, want 1", result.expiredCerts)
	}
	if result.remainingCerts != 1 {
		t.Errorf("processFile() remainingCerts = %d, want 1", result.remainingCerts)
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		expectNil        bool
		expectedExitCode int
		expectedFiles    []string
		minWorkers       int
		maxWorkers       int
	}{
		{
			name:             "valid single file",
			args:             []string{"prog", "file1.json"},
			expectNil:        false,
			expectedExitCode: 0,
			expectedFiles:    []string{"file1.json"},
			minWorkers:       1,
			maxWorkers:       1,
		},
		{
			name:             "valid multiple files",
			args:             []string{"prog", "file1.json", "file2.json", "file3.json"},
			expectNil:        false,
			expectedExitCode: 0,
			expectedFiles:    []string{"file1.json", "file2.json", "file3.json"},
			minWorkers:       1,
			maxWorkers:       3,
		},
		{
			name:             "valid with workers flag",
			args:             []string{"prog", "-workers", "4", "file1.json", "file2.json"},
			expectNil:        false,
			expectedExitCode: 0,
			expectedFiles:    []string{"file1.json", "file2.json"},
			minWorkers:       2,
			maxWorkers:       2,
		},
		{
			name:             "workers less than 1 adjusted to 1",
			args:             []string{"prog", "-workers", "0", "file1.json"},
			expectNil:        false,
			expectedExitCode: 0,
			expectedFiles:    []string{"file1.json"},
			minWorkers:       1,
			maxWorkers:       1,
		},
		{
			name:             "workers more than files adjusted to file count",
			args:             []string{"prog", "-workers", "10", "file1.json", "file2.json"},
			expectNil:        false,
			expectedExitCode: 0,
			expectedFiles:    []string{"file1.json", "file2.json"},
			minWorkers:       2,
			maxWorkers:       2,
		},
		{
			name:             "no files provided",
			args:             []string{"prog"},
			expectNil:        true,
			expectedExitCode: 1,
		},
		{
			name:             "invalid flag",
			args:             []string{"prog", "-invalid", "file1.json"},
			expectNil:        true,
			expectedExitCode: 1,
		},
		{
			name:             "help flag short",
			args:             []string{"prog", "-h"},
			expectNil:        true,
			expectedExitCode: 0,
		},
		{
			name:             "help flag long",
			args:             []string{"prog", "--help"},
			expectNil:        true,
			expectedExitCode: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, exitCode := parseArgs(tt.args)

			if exitCode != tt.expectedExitCode {
				t.Errorf("parseArgs() exitCode = %d, want %d", exitCode, tt.expectedExitCode)
			}

			if tt.expectNil {
				if cfg != nil {
					t.Errorf("parseArgs() expected nil, got %+v", cfg)
				}
				return
			}

			if cfg == nil {
				t.Fatal("parseArgs() returned nil, expected config")
			}

			if len(cfg.files) != len(tt.expectedFiles) {
				t.Errorf("parseArgs() files count = %d, want %d", len(cfg.files), len(tt.expectedFiles))
			}

			for i, file := range tt.expectedFiles {
				if i >= len(cfg.files) {
					break
				}
				if cfg.files[i] != file {
					t.Errorf("parseArgs() files[%d] = %s, want %s", i, cfg.files[i], file)
				}
			}

			if cfg.workers < tt.minWorkers || cfg.workers > tt.maxWorkers {
				t.Errorf("parseArgs() workers = %d, want between %d and %d", cfg.workers, tt.minWorkers, tt.maxWorkers)
			}
		})
	}
}

func TestPrintSummary(t *testing.T) {
	tests := []struct {
		name              string
		results           []cleanerResult
		expectedExit      int
		expectedOutputEnd string // Expected ending of the final summary line
	}{
		{
			name: "all successful with expired certs",
			results: []cleanerResult{
				{
					filename:       "file1.json",
					err:            nil,
					totalCerts:     5,
					expiredCerts:   2,
					remainingCerts: 3,
				},
				{
					filename:       "file2.json",
					err:            nil,
					totalCerts:     3,
					expiredCerts:   1,
					remainingCerts: 2,
				},
			},
			expectedExit:      0,
			expectedOutputEnd: "Processed 2 file(s), 2 successful, 3 total expired certificate(s) removed",
		},
		{
			name: "all successful no expired certs",
			results: []cleanerResult{
				{
					filename:       "file1.json",
					err:            nil,
					totalCerts:     5,
					expiredCerts:   0,
					remainingCerts: 5,
				},
			},
			expectedExit:      0,
			expectedOutputEnd: "Processed 1 file(s), 1 successful, 0 total expired certificate(s) removed",
		},
		{
			name: "some failures",
			results: []cleanerResult{
				{
					filename:       "file1.json",
					err:            nil,
					totalCerts:     5,
					expiredCerts:   2,
					remainingCerts: 3,
				},
				{
					filename:       "file2.json",
					err:            fmt.Errorf("file not found"),
					totalCerts:     0,
					expiredCerts:   0,
					remainingCerts: 0,
				},
			},
			expectedExit:      1,
			expectedOutputEnd: "Processed 2 file(s), 1 successful, 2 total expired certificate(s) removed",
		},
		{
			name: "all failures",
			results: []cleanerResult{
				{
					filename:       "file1.json",
					err:            fmt.Errorf("error 1"),
					totalCerts:     0,
					expiredCerts:   0,
					remainingCerts: 0,
				},
				{
					filename:       "file2.json",
					err:            fmt.Errorf("error 2"),
					totalCerts:     0,
					expiredCerts:   0,
					remainingCerts: 0,
				},
			},
			expectedExit:      1,
			expectedOutputEnd: "Processed 2 file(s), 0 successful, 0 total expired certificate(s) removed",
		},
		{
			name:              "empty results",
			results:           []cleanerResult{},
			expectedExit:      0,
			expectedOutputEnd: "Processed 0 file(s), 0 successful, 0 total expired certificate(s) removed",
		},
		{
			name: "empty file (zero bytes)",
			results: []cleanerResult{
				{
					filename:       "empty.json",
					err:            nil,
					totalCerts:     0,
					expiredCerts:   0,
					remainingCerts: 0,
				},
			},
			expectedExit:      0,
			expectedOutputEnd: "Processed 1 file(s), 1 successful, 1 empty, 0 total expired certificate(s) removed",
		},
		{
			name: "mixed files with empty file",
			results: []cleanerResult{
				{
					filename:       "file1.json",
					err:            nil,
					totalCerts:     5,
					expiredCerts:   2,
					remainingCerts: 3,
				},
				{
					filename:       "empty.json",
					err:            nil,
					totalCerts:     0,
					expiredCerts:   0,
					remainingCerts: 0,
				},
				{
					filename:       "file3.json",
					err:            nil,
					totalCerts:     3,
					expiredCerts:   0,
					remainingCerts: 3,
				},
			},
			expectedExit:      0,
			expectedOutputEnd: "Processed 3 file(s), 3 successful, 1 empty, 2 total expired certificate(s) removed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout to verify the output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			exitCode := printSummary(tt.results)

			// Restore stdout and read captured output
			w.Close()
			os.Stdout = oldStdout
			capturedOutput := make([]byte, 4096)
			n, _ := r.Read(capturedOutput)
			output := string(capturedOutput[:n])

			if exitCode != tt.expectedExit {
				t.Errorf("printSummary() exit code = %d, want %d", exitCode, tt.expectedExit)
			}

			// Verify the final summary line is present in the output
			if !strings.Contains(output, tt.expectedOutputEnd) {
				t.Errorf("printSummary() output does not contain expected line:\nwant: %q\ngot output:\n%s",
					tt.expectedOutputEnd, output)
			}
		})
	}
}
