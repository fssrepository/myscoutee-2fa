# syntax=docker/dockerfile:1
FROM golang:1.26.2-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/myscoutee-2fa ./cmd/myscoutee-2fa \
    && mkdir -p /out/data

FROM scratch
COPY --from=build --chown=65532:65532 /out/myscoutee-2fa /myscoutee-2fa
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
WORKDIR /data
EXPOSE 18083
VOLUME ["/data"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=5 CMD ["/myscoutee-2fa", "healthcheck"]
ENTRYPOINT ["/myscoutee-2fa"]
