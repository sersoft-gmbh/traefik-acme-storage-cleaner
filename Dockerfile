FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod go.sum* ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o traefik-acme-storage-cleaner .


FROM scratch

COPY --from=builder /build/traefik-acme-storage-cleaner /traefik-acme-storage-cleaner

VOLUME ["/data"]

ENTRYPOINT ["/traefik-acme-storage-cleaner"]
