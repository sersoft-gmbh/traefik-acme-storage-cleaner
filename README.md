# Traefik ACME Storage Cleaner

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/sersoft-gmbh/traefik-acme-storage-cleaner)
[![GitHub release](https://img.shields.io/github/release/sersoft-gmbh/traefik-acme-storage-cleaner.svg?style=flat)](https://github.com/sersoft-gmbh/traefik-acme-storage-cleaner/releases/latest)
![Tests](https://github.com/sersoft-gmbh/traefik-acme-storage-cleaner/workflows/Test/badge.svg)
[![codecov](https://codecov.io/gh/sersoft-gmbh/traefik-acme-storage-cleaner/graph/badge.svg?token=c8eVyMfk3z)](https://codecov.io/gh/sersoft-gmbh/traefik-acme-storage-cleaner)

Cleans expired certificates from [Traefik](https://traefik.io/traefik) ACME storage files.

## Overview

This is a small CLI application that reads Traefik ACME storage JSON files, removes expired certificates, and saves the cleaned files back.
The application processes multiple files in parallel for optimal performance.

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

```bash
traefik-acme-storage-cleaner /path/to/acme1.json /path/to/acme2.json
```

### Configure Parallel Workers

By default, the tool uses the number of available CPUs as workers to process multiple files in parallel.
This respects container CPU limits when running in Docker.
If you want to limit the number of workers, you can use the `-workers` flag:

```bash
traefik-acme-storage-cleaner -workers 8 /path/to/acme1.json /path/to/acme2.json
```

### Using Docker

```bash
docker run --rm -v /path/to/acme/storage:/data ghcr.io/sersoft-gmbh/traefik-acme-storage-cleaner:latest /data/acme.json
```


## Docker Image Publishing

Docker images are automatically published to GitHub Container Registry (ghcr.io) on every release. The workflow creates multiple tags:
- Version tag (e.g., `v1.0.0`)
- Major.Minor tag (e.g., `v1.0`)
- Major tag (e.g., `v1`)
- SHA tag for specific commits


## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.
