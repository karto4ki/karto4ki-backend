FROM golang:1.25 AS builder

WORKDIR /app

COPY shared/go.mod shared/go.sum ./shared/
COPY shared/ ./shared/
RUN cd shared && go mod download

COPY identity-service/go.mod identity-service/go.sum ./identity-service/
COPY identity-service/ ./identity-service/
RUN cd identity-service && go mod download

WORKDIR /app/identity-service

RUN CGO_ENABLED=0 go build -o identity-service ./main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root

COPY --from=builder /app/identity-service/identity-service .
COPY --from=builder /app/identity-service/config.yml ./config.yml

EXPOSE 5000

CMD ["./identity-service"]