FROM golang:alpine

# create folder
RUN mkdir -p /service
WORKDIR /service

# get go dependencies
RUN apk add --no-cache \
		git \
	&& go get github.com/julienschmidt/httprouter \
	&& rm -rf /var/cache/apk/*

###
# objdump specific options
###

# Get Go dependencies and binutils
RUN apk add --no-cache \
		binutils \
	&& rm -rf /var/cache/apk/*
RUN go get "github.com/go-ini/ini"

# clean up
RUN apk del --purge \
		git \
	&& rm -rf /var/cache/apk/* yara-3.5.0

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY objdump.go /service
COPY service.conf /service

# build Objdump
RUN go build objdump.go

CMD ["./objdump", "--config=service.conf"]
