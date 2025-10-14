FROM golang:1.25.1-alpine as builder

WORKDIR /app

COPY . .

RUN go build -o monitor .

FROM alpine:latest

COPY --from=builder /app/monitor /usr/local/bin/monitor

CMD ["monitor"]
