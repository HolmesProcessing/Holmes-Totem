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
# gogadget specific options
###

# Get Go ROPGadget dependencies
RUN apk add --no-cache \
		bash \
		build-base \
		python \
		py-pip \
	&& rm -rf /var/cache/apk/*

RUN pip install ropgadget

# clean up
RUN apk del --purge \
		build-base \
		git \
	&& rm -rf /var/cache/apk/* yara-3.5.0

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY gogadget.go /service

# build gogadget
RUN go build gogadget.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["./gogadget", "--config=service.conf"]
