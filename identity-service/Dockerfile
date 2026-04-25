FROM golang:1.25.0 AS builder

WORKDIR /app

ENV GOTOOLCHAIN=local
ENV GOPROXY=http://proxy.golang.org,direct
ENV GOSUMDB=off
ENV GIT_SSL_NO_VERIFY=true

COPY shared/go.mod shared/go.sum ./shared/
COPY shared/ ./shared/
RUN cd shared && go mod download

COPY identity-service/go.mod identity-service/go.sum ./identity-service/
COPY identity-service/ ./identity-service/
RUN cd identity-service && go mod download

WORKDIR /app/identity-service
RUN CGO_ENABLED=0 GOOS=linux go build -o identity-service ./main.go

FROM scratch

WORKDIR /root/

COPY --from=builder /app/identity-service/identity-service .
COPY --from=builder /app/identity-service/config.yml ./config.yml

EXPOSE 5000

CMD ["./identity-service"]
