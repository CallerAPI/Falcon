FROM golang:1.22-bookworm AS build
ARG VERSION
WORKDIR /src
COPY . .
RUN test -n "${VERSION}" && test "${VERSION}" != "dev" || { echo "docker build needs --build-arg VERSION=0.9.23"; exit 1; }
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/falcon ./cmd/falcon

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/falcon /falcon
USER nonroot
EXPOSE 8090
ENTRYPOINT ["/falcon"]
