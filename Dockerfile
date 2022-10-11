ARG EXTRA_LDFLAGS='-w -s'
ARG VERSION="0.0.0-dev.0"
ARG REVISION=""

# Build the manager binary
FROM golang:1.18 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY controllers/ controllers/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "${EXTRA_LDFLAGS} -X main.Version=${VERSION} -X main.Build=${REVISION}" -a -o controller main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source https://github.com/zoomoid/tbctrl
LABEL org.opencontainers.image.description "A Kubernetes controller to auto-approve kubelet serving certificates for TLS traffic from the API server to the kubelet"
LABEL org.opencontainers.image.licenses "Apache-2.0"
LABEL org.opencontainers.image.version ${VERSION}
LABEL org.opencontainers.image.revision ${REVISION}

WORKDIR /
COPY --from=builder /workspace/controller .
USER 65532:65532

ENTRYPOINT ["/controller"]
