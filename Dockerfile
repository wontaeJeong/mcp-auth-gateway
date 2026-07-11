# syntax=docker/dockerfile:1

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=system_ca,target=/etc/ssl/certs/ca-certificates.crt,required=true \
    go mod download
COPY . .
RUN --mount=type=secret,id=system_ca,target=/etc/ssl/certs/ca-certificates.crt,required=true \
    mkdir -p /out && \
    CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway && \
    cp /etc/ssl/certs/ca-certificates.crt /out/ca-certificates.crt

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/gateway /gateway
COPY --from=build /out/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY config.yaml /etc/mcp-auth-gateway/config.yaml
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/gateway"]
# Default config path; k8s deployment overrides this via `args`.
CMD ["-config", "/etc/mcp-auth-gateway/config.yaml"]
