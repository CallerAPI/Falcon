FROM golang:1.23-bookworm AS build
ARG VERSION
WORKDIR /src
COPY . .
RUN test -n "${VERSION}" && test "${VERSION}" != "dev" || { echo "docker build needs --build-arg VERSION=\$(make -s version)"; exit 1; }
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/falcon ./cmd/falcon

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/falcon /falcon
# A new named volume takes the owner of the image directory it mounts over.
# The base image has no shell, so /data is copied in already owned by nonroot.
# Without it, SQLite cannot create the database on a /data volume.
COPY --from=gcr.io/distroless/static-debian12:nonroot --chown=nonroot:nonroot /home/nonroot /data
ENV FALCON_DB_PATH=/data/falcon.db
USER nonroot
EXPOSE 8090
ENTRYPOINT ["/falcon"]
