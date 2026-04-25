FROM golang:1.25.0 AS builder

WORKDIR /app

ENV GOTOOLCHAIN=local
ENV GOPROXY=http://proxy.golang.org,direct
ENV GOSUMDB=off
ENV GIT_SSL_NO_VERIFY=true

COPY shared/go.mod shared/go.sum ./shared/
COPY shared/ ./shared/
RUN cd shared && go mod download

COPY user-service/go.mod user-service/go.sum ./user-service/
COPY user-service/ ./user-service/
RUN cd user-service && go mod download

WORKDIR /app/user-service
RUN CGO_ENABLED=0 GOOS=linux go build -o user-service ./main.go

FROM scratch

WORKDIR /root/

COPY --from=builder /app/user-service/user-service .
COPY --from=builder /app/user-service/config.yml ./config.yml

EXPOSE 8080 50051

CMD ["./user-service"]
