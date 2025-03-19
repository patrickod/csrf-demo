FROM golang:1.24-bookworm as build
RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN go build -o demo

FROM golang:1.24-bookworm
COPY --from=build /app/demo /usr/bin/csrf-demo
CMD ["/usr/bin/csrf-demo"]
