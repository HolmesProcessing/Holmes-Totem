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
# PEV specific options
###

# Get Go PEV dependencies
RUN apk add --no-cache \
		bash \
		build-base \
	&& rm -rf /var/cache/apk/*

RUN apt-get update
RUN apt-get install pev 

# clean up
RUN apk del --purge \
		build-base \
		git \
	&& rm -rf /var/cache/apk/* yara-3.5.0

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY pev.go /service

# build PEV
RUN go build pev.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD [“./pev”, "--config=service.conf"]
