FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.10-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/reconciler ./cmd/reconciler

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/iamangus/stalwart-oidc-reconciler"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/reconciler /reconciler
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/reconciler"]
