FROM golang:1.23-alpine AS builder
RUN apk add -U tzdata
RUN apk --update add ca-certificates
WORKDIR /app
COPY . .
RUN go mod download
RUN go mod verify
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /sse-proxy .
FROM scratch
COPY --from=builder /usr/share/zoneinfo /us/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /sse-proxy .
EXPOSE 80
CMD ["/sse-proxy"]
LABEL org.opencontainers.image.source=https://github.com/Pandry/s3-ssec-proxy
