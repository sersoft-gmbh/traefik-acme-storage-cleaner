package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

// Domain represents a domain with SANs
type Domain struct {
	Main string   `json:"main,omitempty"`
	SANs []string `json:"sans,omitempty"`
}

// CertAndStore allows mapping a TLS certificate to a TLS store
// This matches the Traefik ACME storage format which has a flat structure
type CertAndStore struct {
	Certificate string `json:"certificate,omitempty"`
	Key         string `json:"key,omitempty"`
	Domain      Domain `json:"domain,omitempty"`
	Store       string `json:"store,omitempty"`
}

// Account represents an ACME account
type Account struct {
	Email        string                 `json:"email,omitempty"`
	Registration map[string]interface{} `json:"registration,omitempty"`
	PrivateKey   string                 `json:"privateKey,omitempty"`
	KeyType      string                 `json:"keyType,omitempty"`
}

// StoredData represents the data stored by Traefik
type StoredData struct {
	Account      *Account        `json:"account,omitempty"`
	Certificates []*CertAndStore `json:"certificates,omitempty"`
}

const (
	defaultWorkers = 4
)

type cleanerResult struct {
	filename       string
	err            error
	totalCerts     int
	expiredCerts   int
	remainingCerts int
}

func main() {
	var workers int
	flag.IntVar(&workers, "workers", defaultWorkers, "Number of parallel workers")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <acme-storage-file> [<acme-storage-file>...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if workers < 1 {
		workers = 1
	}

	results := processFiles(files, workers)

	// Print summary
	fmt.Println("\nSummary:")
	fmt.Println("--------")
	totalFiles := 0
	successFiles := 0
	totalExpired := 0
	for _, result := range results {
		totalFiles++
		if result.err != nil {
			fmt.Printf("❌ %s: ERROR - %v\n", result.filename, result.err)
		} else {
			successFiles++
			totalExpired += result.expiredCerts
			if result.expiredCerts > 0 {
				fmt.Printf("✓ %s: Removed %d expired certificate(s), %d remaining\n",
					result.filename, result.expiredCerts, result.remainingCerts)
			} else {
				fmt.Printf("✓ %s: No expired certificates found (%d total)\n",
					result.filename, result.totalCerts)
			}
		}
	}

	fmt.Printf("\nProcessed %d file(s), %d successful, %d total expired certificate(s) removed\n",
		totalFiles, successFiles, totalExpired)

	if successFiles < totalFiles {
		os.Exit(1)
	}
}

func processFiles(files []string, workers int) []cleanerResult {
	jobs := make(chan string, len(files))
	results := make(chan cleanerResult, len(files))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filename := range jobs {
				results <- processFile(filename)
			}
		}()
	}

	// Send jobs
	for _, filename := range files {
		jobs <- filename
	}
	close(jobs)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var allResults []cleanerResult
	for result := range results {
		allResults = append(allResults, result)
	}

	return allResults
}

func processFile(filename string) cleanerResult {
	result := cleanerResult{
		filename: filename,
	}

	// Read the file
	data, err := os.ReadFile(filename)
	if err != nil {
		result.err = fmt.Errorf("failed to read file: %w", err)
		return result
	}

	// Get original file permissions
	fileInfo, err := os.Stat(filename)
	if err != nil {
		result.err = fmt.Errorf("failed to stat file: %w", err)
		return result
	}
	originalPerm := fileInfo.Mode().Perm()

	// Parse JSON into the Traefik ACME storage format
	var storageData map[string]*StoredData
	if err := json.Unmarshal(data, &storageData); err != nil {
		result.err = fmt.Errorf("failed to parse JSON: %w", err)
		return result
	}

	// Process each resolver's certificates
	modified := false
	now := time.Now()

	for resolverName, storedData := range storageData {
		if storedData == nil || storedData.Certificates == nil {
			continue
		}

		originalCount := len(storedData.Certificates)
		result.totalCerts += originalCount

		// Filter out expired certificates
		var validCerts []*CertAndStore
		for _, certAndStore := range storedData.Certificates {
			expired, parseErr := isExpired(certAndStore, now)
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to parse certificate for %s: %v (treating as expired)\n",
					formatDomain(certAndStore.Domain), parseErr)
			}
			if expired {
				result.expiredCerts++
				fmt.Printf("Removing expired certificate for %s in resolver %s\n",
					formatDomain(certAndStore.Domain), resolverName)
			} else {
				validCerts = append(validCerts, certAndStore)
			}
		}

		if len(validCerts) < originalCount {
			storedData.Certificates = validCerts
			modified = true
		}
	}

	result.remainingCerts = result.totalCerts - result.expiredCerts

	// Save the file if modified
	if modified {
		updatedData, err := json.MarshalIndent(storageData, "", "  ")
		if err != nil {
			result.err = fmt.Errorf("failed to marshal JSON: %w", err)
			return result
		}

		// Write with original permissions
		if err := os.WriteFile(filename, updatedData, originalPerm); err != nil {
			result.err = fmt.Errorf("failed to write file: %w", err)
			return result
		}
	}

	return result
}

func isExpired(certAndStore *CertAndStore, now time.Time) (bool, error) {
	if certAndStore == nil || len(certAndStore.Certificate) == 0 {
		return true, fmt.Errorf("certificate data is empty")
	}

	// Parse the certificate
	block, _ := pem.Decode([]byte(certAndStore.Certificate))
	if block == nil {
		// Not PEM encoded, try to parse as DER
		cert, err := x509.ParseCertificate([]byte(certAndStore.Certificate))
		if err != nil {
			return true, fmt.Errorf("failed to parse certificate: %w", err)
		}
		return now.After(cert.NotAfter), nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return now.After(cert.NotAfter), nil
}

func formatDomain(domain Domain) string {
	if domain.Main == "" {
		return "unknown"
	}
	if len(domain.SANs) == 0 {
		return domain.Main
	}
	return fmt.Sprintf("%s (SANs: %v)", domain.Main, domain.SANs)
}
