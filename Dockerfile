FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/towerman-relay ./cmd/towerman-relay

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/towerman-relay /towerman-relay
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/towerman-relay"]
