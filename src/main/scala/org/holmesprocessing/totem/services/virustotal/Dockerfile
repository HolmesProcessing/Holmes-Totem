FROM golang:alpine

# Get Go dependencies
RUN apk add --no-cache \
		git \
	&& rm -rf /var/cache/apk/*
RUN go get github.com/julienschmidt/httprouter

# Setup service
RUN mkdir -p /service
ADD . /service

WORKDIR /service
RUN go build -o vtsample

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

ENTRYPOINT ["/service/vtsample", "-config=/service/service.conf"] 
