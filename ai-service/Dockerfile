FROM golang:1.25 AS builder

WORKDIR /app

COPY shared/go.mod shared/go.sum ./shared/
COPY shared/ ./shared/
RUN cd shared && go mod download

COPY ai-service/go.mod ai-service/go.sum ./ai-service/
COPY ai-service/ ./ai-service/
RUN cd ai-service && go mod download

COPY keys/ ./keys/

WORKDIR /app/ai-service

RUN CGO_ENABLED=0 go build -o ai-service ./cmd/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/ai-service/ai-service .
COPY --from=builder /app/ai-service/config.yml ./config.yml
COPY --from=builder /app/keys/ ./keys/

EXPOSE 8083

CMD ["./ai-service"]