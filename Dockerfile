# syntax=docker/dockerfile:1.6
#
# Multi-arch image. Buildx feeds TARGETOS/TARGETARCH per platform so we can
# produce linux/amd64 and linux/arm64 from the same Dockerfile.

# --- build stage ---
FROM --platform=$BUILDPLATFORM golang:1.24 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

# Cache modules first so source changes don't bust the dependency layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/request-validator ./cmd

# --- runtime stage ---
FROM gcr.io/distroless/static:nonroot

ARG VERSION=dev

LABEL org.opencontainers.image.title="request-validator"
LABEL org.opencontainers.image.description="Generic Envoy/Istio ext-authz HTTP service driven by a CEL policy."
LABEL org.opencontainers.image.source="https://github.com/achetronic/request-validator"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="${VERSION}"

WORKDIR /
COPY --from=build /out/request-validator /request-validator
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/request-validator"]
