# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=1.0.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/mcpgate ./cmd/mcpgate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/mcpgate /usr/local/bin/mcpgate
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mcpgate"]
CMD ["--help"]
