# Multi-stage: build in container. Used by make docker and goreleaser (buildx multi-arch).
# Use Debian-based image: Alpine arm64 often hits "exec format error" under QEMU on amd64 CI.
FROM golang:1.24-bookworm AS builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o blackbox_exporter .

FROM quay.io/prometheus/busybox:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

COPY --from=builder /src/blackbox_exporter /bin/blackbox_exporter
COPY blackbox.yml /etc/blackbox_exporter/config.yml

EXPOSE      9115
ENTRYPOINT [ "/bin/blackbox_exporter" ]
CMD        [ "--config.file=/etc/blackbox_exporter/config.yml" ]
