FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY ai-service/go.mod ai-service/go.sum ./
RUN go mod download

# Copy source code
COPY ai-service/ ./
COPY shared/ ./shared/

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/main.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata

# Copy binary
COPY --from=builder /app/main .

# Copy config
COPY ai-service/config.yml .

# Create non-root user
RUN adduser -D -g '' appuser
USER appuser

EXPOSE 8083

CMD ["./main"]
