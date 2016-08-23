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
# virustotal specific options
###

# clean up
RUN apk del --purge \
		git \
	&& rm -rf /var/cache/apk/* yara-3.5.0

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY vtsample.go /service

# build vtsample
RUN go build vtsample.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf
CMD ["./vtsample", "-config=service.conf"] 
