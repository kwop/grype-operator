# Build the operator binary
FROM golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache git

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o grype-operator cmd/main.go

# Grype binary stage — pin version, use digest in production
FROM anchore/grype:v0.92.0 AS grype

# Final image — needs shell for grype subprocess
FROM alpine:3.21
RUN apk add --no-cache ca-certificates

COPY --from=grype /grype /usr/local/bin/grype
COPY --from=builder /workspace/grype-operator /usr/local/bin/grype-operator

USER 65534:65534

ENTRYPOINT ["grype-operator"]
