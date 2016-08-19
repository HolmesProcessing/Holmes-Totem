FROM golang:alpine

# Get Go dependencies and binutils
RUN apk add --no-cache \
		git \
		binutils \
	&& rm -rf /var/cache/apk/*
RUN go get "github.com/go-ini/ini"
RUN go get "github.com/julienschmidt/httprouter"

# Add relevant files to the container.
RUN mkdir -p /service
ADD LICENSE /service
ADD README.md /service
ADD objdump.go /service

# Change the working directory.
WORKDIR /service

# Build Objdump.
RUN go build objdump.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["/service/objdump", "--config=service.conf"]
