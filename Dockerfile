FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/bouncing ./cmd/bouncing

FROM scratch
COPY --from=builder /bin/bouncing /bouncing
EXPOSE 3117
ENTRYPOINT ["/bouncing"]
CMD ["serve"]
