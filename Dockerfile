# Base images are pinned by digest: the sha-<commit> tag depends on it. A
# floating tag would rebuild different bytes for the same commit.
# Update: docker buildx imagetools inspect <image:tag> --format '{{.Manifest.Digest}}'
#         After updating, republish the image and record the new image digest
#         in the release.
FROM golang:1.26-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY . .
# GOTOOLCHAIN=local builds with the Go of the digest-pinned base image and never
# downloads another toolchain; that Go must satisfy the go directive in go.mod.
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/veriprov ./cmd/veriprov

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/veriprov /veriprov
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/veriprov"]
