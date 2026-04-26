FROM golang:1.25.0 AS builder

WORKDIR /app

ENV GOTOOLCHAIN=local
ENV GOPROXY=http://proxy.golang.org,direct
ENV GOSUMDB=off
ENV GIT_SSL_NO_VERIFY=true

COPY shared/go.mod shared/go.sum ./shared/
COPY shared/ ./shared/
RUN cd shared && go mod download

COPY filestorage-service/go.mod filestorage-service/go.sum ./filestorage-service/
COPY filestorage-service/ ./filestorage-service/
RUN cd filestorage-service && go mod download

WORKDIR /app/filestorage-service
RUN CGO_ENABLED=0 GOOS=linux go build -o filestorage-service ./cmd/main.go

FROM scratch

WORKDIR /root/

COPY --from=builder /app/filestorage-service/filestorage-service .
COPY --from=builder /app/filestorage-service/config.yml ./config.yml
COPY keys/ ./keys/

EXPOSE 8081

CMD ["./filestorage-service"]
