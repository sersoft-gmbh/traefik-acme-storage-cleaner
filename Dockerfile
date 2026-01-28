FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
ENV GOCACHE=/root/.cache/go-build
ENV CGO_ENABLED=0

COPY go.mod go.sum* ./
RUN go mod download

COPY *.go ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags '-extldflags "-static"' -o traefik-acme-storage-cleaner .


FROM scratch

COPY --from=builder /build/traefik-acme-storage-cleaner /traefik-acme-storage-cleaner

VOLUME ["/data"]

ENTRYPOINT ["/traefik-acme-storage-cleaner"]
