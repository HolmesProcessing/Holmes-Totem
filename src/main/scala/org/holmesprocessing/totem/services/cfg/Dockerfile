FROM golang:alpine

# create folder
RUN mkdir -p /service
WORKDIR /service

# add repository for capstone
RUN echo "@testing http://dl-3.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories

# get go dependencies
RUN apk add --no-cache \
		git \
	&& go get github.com/julienschmidt/httprouter \
	&& rm -rf /var/cache/apk/*

###
# CFG specific options
###

# Get Go CFG dependencies
RUN apk add --no-cache \
		bash \
		build-base \
		binutils \
		binutils-dev \
		capstone@testing \
		git \
	&& git clone https://bitbucket.org/vusec/nucleus.git \
	&& rm -rf /var/cache/apk/*

# clean up
RUN apk del --purge \
		build-base \
		git \
	&& rm -rf /var/cache/apk/* yara-3.5.0

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY /nucleus /service/nucleus
COPY cfg.go /service

# build nucleus
RUN cd /service/nucleus \
    && make

# build CFG
RUN go build cfg.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["./cfg", "--config=service.conf"]
