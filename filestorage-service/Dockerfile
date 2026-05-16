FROM golang:1.25 AS builder

WORKDIR /app

COPY shared/go.mod shared/go.sum ./shared/
COPY shared/ ./shared/
RUN cd shared && go mod download

COPY filestorage-service/go.mod filestorage-service/go.sum ./filestorage-service/
COPY filestorage-service/ ./filestorage-service/
RUN cd filestorage-service && go mod download

WORKDIR /app/filestorage-service
RUN CGO_ENABLED=0 GOOS=linux go build -o filestorage-service ./cmd/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/filestorage-service/filestorage-service .
COPY --from=builder /app/filestorage-service/config.yml ./config.yml

EXPOSE 8081

CMD ["./filestorage-service"]