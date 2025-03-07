FROM golang:1.21-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git ca-certificates tzdata build-base

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/server ./cmd/server

# Create a minimal production image
FROM alpine:3.18

# Add certificates
RUN apk --no-cache add ca-certificates tzdata

# Set working directory
WORKDIR /app

# Create directories for certificates and data
RUN mkdir -p /app/certs /app/data

# Copy binary from builder stage
COPY --from=builder /go/bin/server /app/server

# Copy default config
COPY config.yaml /app/config.yaml

# Expose ports
EXPOSE 8443

# Set entrypoint
ENTRYPOINT ["/app/server"]
CMD ["--config", "config.yaml"]