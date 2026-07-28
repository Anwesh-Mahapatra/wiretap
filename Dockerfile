# Builds wiretap's Go binaries -- tracepump and wiretapd -- from one shared
# build stage. Multi-stage so each final image ships only a static binary,
# not a Go toolchain. The two runtime stages are named build targets (see
# docker-compose.yml's "build.target"), so one Dockerfile serves both
# services without duplicating the dependency-download/compile step.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/tracepump ./cmd/tracepump
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/wiretapd ./cmd/wiretapd

FROM gcr.io/distroless/static-debian12:nonroot AS tracepump
COPY --from=build /out/tracepump /tracepump
ENTRYPOINT ["/tracepump"]

FROM gcr.io/distroless/static-debian12:nonroot AS wiretapd
COPY --from=build /out/wiretapd /wiretapd
ENTRYPOINT ["/wiretapd"]
