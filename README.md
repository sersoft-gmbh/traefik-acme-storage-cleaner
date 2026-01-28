# traefik-acme-storage-cleaner

Cleans expired certificates from Traefik ACME storage files.

## Overview

This is a Go CLI application that reads Traefik ACME storage JSON files, identifies and removes expired certificates, and saves the cleaned files back. The application processes multiple files in parallel for optimal performance.

## Features

- ✅ Reads Traefik ACME storage JSON files
- ✅ Identifies expired certificates using certificate expiration dates
- ✅ Removes expired certificates while preserving valid ones
- ✅ Processes multiple files in parallel (configurable worker count)
- ✅ Maintains JSON structure compatible with Traefik
- ✅ Provides detailed summary of operations
- ✅ Available as a standalone binary or Docker container

## Installation

### Using Go

```bash
go install github.com/sersoft-gmbh/traefik-acme-storage-cleaner@latest
```

### Using Docker

```bash
docker pull ghcr.io/sersoft-gmbh/traefik-acme-storage-cleaner:latest
```

### Building from Source

```bash
git clone https://github.com/sersoft-gmbh/traefik-acme-storage-cleaner.git
cd traefik-acme-storage-cleaner
go build -o traefik-acme-storage-cleaner .
```

## Usage

### Basic Usage

```bash
traefik-acme-storage-cleaner /path/to/acme.json
```

### Process Multiple Files

```bash
traefik-acme-storage-cleaner /path/to/acme1.json /path/to/acme2.json
```

### Configure Parallel Workers

```bash
traefik-acme-storage-cleaner -workers 8 /path/to/acme.json
```

### Using Docker

```bash
docker run --rm -v /path/to/acme/storage:/data ghcr.io/sersoft-gmbh/traefik-acme-storage-cleaner:latest /data/acme.json
```

## Command-Line Options

- `-workers int` - Number of parallel workers (default: 4)

## Output Example

```
Removing expired certificate for expired.example.com in resolver myresolver

Summary:
--------
✓ /path/to/acme.json: Removed 2 expired certificate(s), 5 remaining

Processed 1 file(s), 1 successful, 2 total expired certificate(s) removed
```

## ACME Storage Format

The tool expects Traefik ACME storage files in the following JSON format:

```json
{
  "myresolver": {
    "account": {
      "email": "user@example.com",
      "registration": {},
      "privateKey": "...",
      "keyType": "RSA4096"
    },
    "certificates": [
      {
        "domain": {
          "main": "example.com",
          "sans": ["www.example.com"]
        },
        "certificate": "-----BEGIN CERTIFICATE-----\n...",
        "key": "-----BEGIN PRIVATE KEY-----\n..."
      }
    ]
  }
}
```

## Docker Image Publishing

Docker images are automatically published to GitHub Container Registry (ghcr.io) on every release. The workflow creates multiple tags:
- Version tag (e.g., `v1.0.0`)
- Major.Minor tag (e.g., `v1.0`)
- Major tag (e.g., `v1`)
- SHA tag for specific commits

## Development

### Building

```bash
go build -o traefik-acme-storage-cleaner .
```

### Building Docker Image

```bash
docker build -t traefik-acme-storage-cleaner .
```

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

