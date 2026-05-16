FROM golang:1.25 AS builder

WORKDIR /app

COPY shared/go.mod shared/go.sum ./shared/
COPY shared/ ./shared/
RUN cd shared && go mod download

COPY user-service/go.mod user-service/go.sum ./user-service/
COPY user-service/ ./user-service/
RUN cd user-service && go mod download

COPY keys/ ./keys/

WORKDIR /app/user-service

RUN CGO_ENABLED=0 go build -o user-service ./main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/user-service/user-service .
COPY --from=builder /app/user-service/config.yml ./config.yml
COPY --from=builder /app/keys/ ./keys/

EXPOSE 8080

CMD ["./user-service"]