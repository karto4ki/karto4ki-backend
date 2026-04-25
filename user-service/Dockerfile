FROM golang:1.25.0 AS builder

WORKDIR /app/user-service

# Копируем shared в подпапку (для replace)
COPY shared/ ./shared/
RUN cd shared && go mod download

# Копируем go.mod и go.sum
COPY user-service/go.mod user-service/go.sum ./
RUN go mod download

COPY user-service/ ./

WORKDIR /app/user-service

# Статическая сборка (CGO off)
RUN CGO_ENABLED=0 go build -o user-service ./main.go   # или ./cmd/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/user-service/user-service .
COPY --from=builder /app/user-service/config.yml ./config.yml

RUN chmod +x /root/user-service

EXPOSE 8080 50051

CMD ["./user-service"]