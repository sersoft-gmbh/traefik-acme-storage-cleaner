# Traefik ACME Storage Cleaner - Copilot Instructions

## Repository Overview

This is a small, focused Go CLI application that cleans expired certificates from Traefik ACME storage JSON files. The application is designed for simplicity and performance, processing multiple files in parallel using worker pools.

**Repository Statistics:**
- Language: Go 1.25
- Size: ~12 files (excluding dependencies)
- Type: CLI application
- Main Dependencies: github.com/traefik/traefik/v3 v3.6.7

## Project Structure

```
.
├── main.go                 # Main application code (single file application)
├── go.mod                  # Go module definition
├── go.sum                  # Go dependencies checksums
├── Dockerfile              # Multi-stage Docker build
├── README.md               # User documentation
├── LICENSE                 # License file
└── .github/
    ├── workflows/
    │   ├── build.yml       # CI build workflow (multi-OS, multi-arch)
    │   ├── docker-publish.yml  # Docker image publishing on release
    │   └── enable-auto-merge.yml
    ├── dependabot.yml      # Dependabot configuration
    └── CODEOWNERS          # Code ownership configuration
```

## Building and Testing

### Prerequisites
- Go 1.25 or later (specified in go.mod)
- No additional tools required for basic builds

### Build Commands

**Standard build:**
```bash
go build .
```
This creates the `traefik-acme-storage-cleaner` binary in the current directory.

**Build time:** Approximately 2-3 minutes on first build (downloads dependencies), ~5-10 seconds on subsequent builds.

**Cross-platform builds:**
The project supports multiple platforms via environment variables:
```bash
# Linux AMD64 (default)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build .

# macOS ARM64
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build .

# Windows AMD64
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build .
```

**Important:** CGO_ENABLED=0 must be set to disable glibc linking for portability.

### Docker Build

**Build Docker image:**
```bash
docker build -t traefik-acme-storage-cleaner .
```

The Dockerfile uses a multi-stage build:
1. Stage 1: golang:1.25-alpine builder with caching
2. Stage 2: scratch base for minimal image size

**Build time:** ~3-5 minutes on first build, faster with Docker layer caching.

### Testing

**No formal test suite exists.** The repository does not contain any `*_test.go` files or testing infrastructure.

To manually test the application:
1. Build the binary: `go build .`
2. Create a test ACME JSON file with sample certificates
3. Run: `./traefik-acme-storage-cleaner test-acme.json`
4. Verify the output shows certificate processing

### Running the Application

```bash
# Basic usage
./traefik-acme-storage-cleaner /path/to/acme.json

# Multiple files
./traefik-acme-storage-cleaner file1.json file2.json file3.json

# Custom worker count
./traefik-acme-storage-cleaner -workers 8 /path/to/acme.json

# Docker
docker run --rm -v /path/to/acme:/data ghcr.io/sersoft-gmbh/traefik-acme-storage-cleaner:latest /data/acme.json
```

## CI/CD Pipeline

### Build Workflow (.github/workflows/build.yml)
- Triggers on: push to main, pull requests to main
- Tests: Builds for 6 combinations (linux/darwin/windows × amd64/arm64)
- Go version: Read from go.mod using actions/setup-go@v6
- Each build runs with `CGO_ENABLED=0` and uses Go module caching

### Docker Publish Workflow (.github/workflows/docker-publish.yml)
- Triggers on: Release published
- Publishes to: GitHub Container Registry (ghcr.io)
- Tags generated:
  - `vX.Y.Z` (full semver)
  - `vX.Y` (major.minor)
  - `vX` (major)
  - `sha-<commit>` (git SHA)

## Code Architecture

### Main Components

**main.go** contains all application logic:
- `main()`: Entry point, handles CLI flags and orchestrates processing
- `processFiles()`: Worker pool implementation for parallel file processing
- `processFile()`: Processes a single ACME storage file
- `isExpired()`: Parses and checks certificate expiration
- `formatDomain()`: Formats domain information for display

### Key Data Structures

The application uses Traefik's ACME data structures:
- `map[string]*acme.StoredData`: Top-level storage format (resolver name → data)
- `acme.StoredData`: Contains certificate array and account info
- `acme.CertAndStore`: Individual certificate with domain and store info
- `types.Domain`: Domain with Main and SANs (Subject Alternative Names)

### Parallel Processing

The application uses a worker pool pattern:
- Default workers: `runtime.GOMAXPROCS(0)` (respects container CPU limits)
- Configurable via `-workers` flag
- Files processed concurrently using channels and goroutines
- Results collected and summarized at the end

### Error Handling

- File read errors: Reported and skipped
- Certificate parsing errors: Warning printed, certificate treated as expired
- Partial failures: Application continues processing remaining files
- Exit code: 0 if all files processed successfully, 1 if any failures

## Coding Conventions

### Style Guidelines
- Standard Go formatting (use `go fmt`)
- Minimal comments (code is self-documenting)
- Error messages written to `os.Stderr`
- Progress/status messages to `os.Stdout`
- Use emoji in output: ✓ for success, ❌ for errors

### File Handling
- Preserve original file permissions when writing
- Use `os.ReadFile` and `os.WriteFile` (not deprecated `ioutil`)
- Only write file if modifications were made

### Dependencies
- Minimize external dependencies
- Primary dependency: github.com/traefik/traefik/v3 for ACME types
- Use Go standard library whenever possible

## Common Tasks

### Adding New Command-Line Flags
1. Declare flag variable in main()
2. Use `flag.IntVar`, `flag.StringVar`, etc.
3. Ensure `flag.Parse()` is called before accessing
4. Update usage message if needed

### Modifying Certificate Logic
- Certificate expiration check: See `isExpired()` function
- Handles both PEM-encoded and DER format certificates
- Uses Go's `crypto/x509` package for parsing

### Updating Dependencies
```bash
# Update specific dependency
go get github.com/traefik/traefik/v3@latest

# Update all dependencies
go get -u ./...

# Tidy modules
go mod tidy
```

### Creating a Release
1. Tag the commit: `git tag vX.Y.Z`
2. Push tag: `git push origin vX.Y.Z`
3. Create GitHub release (triggers docker-publish workflow)
4. Docker images automatically published to ghcr.io

## Important Notes

### Always Remember
- This is a **single-file application** (main.go) - keep it simple
- **No tests exist** - don't try to run `go test`
- **CGO_ENABLED=0** must always be set for builds to ensure static linking
- Worker count defaults to available CPUs (respects container limits)
- The application modifies files in-place (preserves permissions)
- Files are processed in parallel - order is not guaranteed

### Known Limitations
- No dry-run mode
- No backup functionality (modifies files directly)
- No validation that input files are valid ACME storage format before writing
- Error handling treats unparseable certificates as expired (safe default)

### Validation Steps for Changes
Since there are no automated tests:
1. Build the application: `go build .`
2. Create or obtain a test ACME JSON file
3. Run the application on the test file
4. Verify:
   - Application completes without crashing
   - Output messages are correct and formatted properly
   - File is modified correctly (if certificates were expired)
   - File permissions are preserved
   - Multi-file processing works correctly
5. Test with edge cases:
   - Empty ACME file: `{}`
   - File with no expired certificates
   - File with all expired certificates
   - Multiple files at once
   - Invalid JSON (should fail gracefully)

### Build Troubleshooting
- If build fails with dependency errors: Run `go mod download` first
- If build is slow: Go is downloading dependencies (first build only)
- If binary doesn't run on target system: Ensure CGO_ENABLED=0 was set during build
- If Docker build fails: Check that go.mod and go.sum are in sync

## Example Workflow for Code Changes

1. Modify main.go
2. Format code: `go fmt main.go`
3. Build: `go build .`
4. Test manually with sample files
5. If working, commit changes
6. Push to branch and create PR
7. CI will build for all platforms automatically
8. Merge when builds pass
