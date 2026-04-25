FROM golang:1.25.0 AS builder

WORKDIR /app/identity-service

COPY shared/ ./shared/
COPY identity-service/go.mod identity-service/go.sum ./
RUN go mod download

COPY identity-service/ ./

RUN CGO_ENABLED=0 go build -o identity-service ./main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/identity-service/identity-service .
COPY --from=builder /app/identity-service/config.yml ./config.yml

EXPOSE 5000

CMD ["./identity-service"]