# Multi-stage: build in container. Used by make docker and goreleaser (buildx multi-arch).
FROM golang:1.24-alpine AS builder
WORKDIR /src
RUN apk add --no-cache ca-certificates
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
