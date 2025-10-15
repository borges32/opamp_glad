# opamp/Dockerfile
FROM golang:1.23.2 AS builder

# Copy the entire source code to the container
WORKDIR /src/opamp-go
COPY . .

# Change to the examples directory (where the correct go.mod is)
WORKDIR /src/opamp-go/internal/examples

# Build the example server (with UI)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/opamp-server ./server

FROM alpine:3.20
# Copy binary and UI folder exactly as the example server expects
WORKDIR /app
COPY --from=builder /tmp/opamp-server /usr/local/bin/opamp-server
COPY --from=builder /src/opamp-go/internal/examples/server/uisrv /app/uisrv
# (opcional) se quiser copiar exemplos de certs, ajuste este COPY:
# COPY --from=builder /src/opamp-go/internal/examples/certs /app/certs

EXPOSE 4320 4321
# Garanta que o processo rode no /app (onde está /app/uisrv/...)
WORKDIR /app
ENTRYPOINT ["/usr/local/bin/opamp-server"]