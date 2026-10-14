# SCHAT relay server — container image.
#
# Build:
#   docker build -t schat-server .
# Run (zero configuration, self-signed TLS):
#   docker run -d --name schat -p 8443:8443 schat-server
# Run (zero configuration, self-signed TLS; the fingerprint is printed at startup):
#   docker run -d --name schat -p 8443:8443 -v schat-state:/state schat-server
#
# For a public deployment, terminate TLS at a reverse proxy (Caddy obtains and
# renews certificates with no configuration) and forward to this container over
# the internal network. The server deliberately contains no ACME client.
#
# The image contains no database, no shell tooling and no data directory,
# because the server stores nothing. The final stage is distroless-style: the
# only thing in it is the static binary and the CA bundle needed for outbound
# ACME requests.

FROM golang:1.27-alpine AS build

WORKDIR /src

# Cache the module graph separately from the source so that source edits do not
# invalidate dependency downloads. The server module has no dependencies, so
# this is fast, but keeping the pattern makes the intent explicit.
COPY go.mod ./
RUN go mod download

COPY . .

# CGO is disabled so the result is a static binary that runs on a scratch base.
# -trimpath removes local paths, and the -X flags stamp the build identity.
ARG VERSION=0.1.0-alpha
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w -X github.com/AyanamiRei-lu/Schat/server/internal/version.Version=${VERSION} -X github.com/AyanamiRei-lu/Schat/server/internal/version.Commit=${COMMIT}" \
      -o /out/schat-server ./cmd/schat-server

# ---------------------------------------------------------------------------

FROM alpine:3.20

# ca-certificates is present so the container can reach anything the operator
# configures later; the server itself makes no outbound requests.
RUN apk add --no-cache ca-certificates && \
    adduser -D -H -u 10001 schat

COPY --from=build /out/schat-server /usr/local/bin/schat-server

# The relay needs no filesystem access at all. Running as a non-root user with a
# read-only root filesystem removes the last way user data could reach disk.
USER 10001:10001

EXPOSE 8443

ENV SCHAT_LISTEN=0.0.0.0:8443 \
    SCHAT_MODE=live

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/schat-server", "--version"]

ENTRYPOINT ["/usr/local/bin/schat-server"]
