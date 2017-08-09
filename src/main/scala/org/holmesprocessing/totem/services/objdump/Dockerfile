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

# Get binutils : objdump is part of binutils
RUN apk add --no-cache \
		binutils \ 
	&& rm -rf /var/cache/apk/*

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY objdump.go /service

# build Objdump
RUN go build objdump.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["./objdump", "--config=service.conf"]
