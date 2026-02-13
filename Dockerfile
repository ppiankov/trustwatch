FROM golang:1.25-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.Version=${VERSION}" -o /trustwatch ./cmd/trustwatch

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /trustwatch /trustwatch
ENTRYPOINT ["/trustwatch"]
