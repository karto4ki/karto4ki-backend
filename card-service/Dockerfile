FROM golang:1.25.0 AS builder

WORKDIR /app

COPY shared/go.mod shared/go.sum ./shared/
COPY shared/ ./shared/
RUN cd shared && go mod download

COPY card-service/go.mod card-service/go.sum ./card-service/
COPY card-service/ ./card-service/
RUN cd card-service && go mod download

COPY keys/ ./keys/

WORKDIR /app/card-service

RUN CGO_ENABLED=0 go build -o card-service ./cmd/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/card-service/card-service .
COPY --from=builder /app/card-service/config.yml ./config.yml
COPY --from=builder /app/keys/ ./keys/

EXPOSE 8082

CMD ["./card-service"]