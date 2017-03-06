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
# pdfparse specific options
###

# Get Go pdfparse dependencies
RUN apk add --no-cache \
		bash \
		build-base \
		python \
		py-pip \
	&& rm -rf /var/cache/apk/*

# clean up
RUN apk del --purge \
		build-base \
		git \
	&& rm -rf /var/cache/apk/* yara-3.5.0

RUN pip install pdfparse --upgrade

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY pdfparse.go /service
# build pdfparse
RUN go build pdfparse.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["./pdfparse", "--config=service.conf"]
