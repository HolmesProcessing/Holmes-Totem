FROM golang:alpine

# Get Go dependencies
RUN apk add --no-cache git
RUN go get github.com/julienschmidt/httprouter

# Setup service
RUN mkdir -p /service
ADD . /service

WORKDIR /service
RUN go build -o vtsample

ENTRYPOINT ["/service/vtsample", "-config=/service/service.conf"] 
