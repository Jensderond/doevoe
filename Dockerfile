FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /doevoe ./cmd/doevoe

FROM gcr.io/distroless/static-debian12
COPY --from=build /doevoe /doevoe
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/doevoe"]
