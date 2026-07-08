FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/gateway /gateway
COPY config.yaml /etc/mcp-auth-gateway/config.yaml
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/gateway", "-config", "/etc/mcp-auth-gateway/config.yaml"]
