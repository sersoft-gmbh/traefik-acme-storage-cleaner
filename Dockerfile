# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download || true

# Copy source code
COPY *.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o traefik-acme-storage-cleaner .

# Final stage - using scratch for minimal image
FROM scratch

# Copy the binary from builder
COPY --from=builder /build/traefik-acme-storage-cleaner /traefik-acme-storage-cleaner

# Create a volume for the ACME storage files
VOLUME ["/data"]

ENTRYPOINT ["/traefik-acme-storage-cleaner"]
