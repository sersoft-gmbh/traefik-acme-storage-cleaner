package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/traefik/traefik/v3/pkg/provider/acme"
	"github.com/traefik/traefik/v3/pkg/types"
)

func defaultWorkers() int {
	// GOMAXPROCS(0) returns the current setting, which respects container CPU limits
	return runtime.GOMAXPROCS(0)
}

type cleanerResult struct {
	filename       string
	err            error
	totalCerts     int
	expiredCerts   int
	remainingCerts int
}

type config struct {
	files   []string
	workers int
}

// parseArgs parses command-line arguments and returns the configuration.
// Returns nil if arguments are invalid (help/usage should be displayed).
func parseArgs(args []string) *config {
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	workers := fs.Int("workers", defaultWorkers(), "Number of parallel workers")
	
	if err := fs.Parse(args[1:]); err != nil {
		return nil
	}

	files := fs.Args()
	if len(files) == 0 {
		return nil
	}

	// Adjust worker count
	w := *workers
	if w < 1 {
		w = 1
	} else if w > len(files) {
		w = len(files)
	}

	return &config{
		files:   files,
		workers: w,
	}
}

// printSummary prints the results summary and returns the exit code.
func printSummary(results []cleanerResult) int {
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
		return 1
	}
	return 0
}

func main() {
	cfg := parseArgs(os.Args)
	if cfg == nil {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <acme-storage-file> [<acme-storage-file>...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	results := processFiles(cfg.files, cfg.workers)
	exitCode := printSummary(results)
	os.Exit(exitCode)
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
	var storageData map[string]*acme.StoredData
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
		var validCerts []*acme.CertAndStore
		for _, certAndStore := range storedData.Certificates {
			expired, parseErr := isExpired(certAndStore.Certificate, now)
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

func isExpired(certificate acme.Certificate, now time.Time) (bool, error) {
	if len(certificate.Certificate) == 0 {
		return true, fmt.Errorf("certificate data is empty")
	}

	// Parse the certificate
	block, _ := pem.Decode(certificate.Certificate)
	if block == nil {
		// Not PEM encoded, try to parse as DER
		cert, err := x509.ParseCertificate(certificate.Certificate)
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

func formatDomain(domain types.Domain) string {
	if domain.Main == "" {
		return "unknown"
	}
	if len(domain.SANs) == 0 {
		return domain.Main
	}
	return fmt.Sprintf("%s (SANs: %v)", domain.Main, domain.SANs)
}
