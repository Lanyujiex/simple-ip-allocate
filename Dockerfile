# Build the ip-allocator binary
# FROM golang:1.24.4 AS builder
FROM registry.cn-beijing.aliyuncs.com/dproxy/golang:1.24.1-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ENV GO111MODULE=on  GOPROXY=https://goproxy.cn,direct
WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.sum ./
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY pkg/ pkg/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o ip-allocator main.go

# final
FROM harbor-ops.ebtech.com/base/ubuntu:22.04-build
ARG ENVIRONMENT=dev

WORKDIR /app
COPY --from=builder /workspace/ip-allocator .

ENTRYPOINT ["/app/ip-allocator"]
