# Stage 1: Build
FROM golang:1.25.3-alpine AS builder

RUN go install github.com/a-h/templ/cmd/templ@latest

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN templ generate
RUN CGO_ENABLED=0 go build -o /app/bin/server ./cmd/server

# Stage 2: Run
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/bin/server .
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/static ./static

EXPOSE 8080

CMD ["./server"]
