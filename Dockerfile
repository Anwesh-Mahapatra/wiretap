# Builds the tracepump binary (see cmd/tracepump). Multi-stage so the final
# image ships only the static binary, not a Go toolchain.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/tracepump ./cmd/tracepump

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /out/tracepump /tracepump
ENTRYPOINT ["/tracepump"]
