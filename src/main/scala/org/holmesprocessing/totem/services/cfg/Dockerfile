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
# cfg specific options
###

# get go cfg dependencies
RUN apk add --no-cache \
		bash \
		build-base \
		binutils \
		binutils-dev \
<<<<<<< HEAD
		g++ \
=======
		capstone@testing \
>>>>>>> d9903c63fb047a6086b8f31c3b34bbd3b4eb8fcc
		git \
		make \
	&& git clone https://github.com/aquynh/capstone \
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
COPY cfg.go /service

# build capstone
RUN cd /service/capstone \
    && ./make.sh \
	&& su; ./make.sh install

# workaround for bfd.h error (see https://github.com/yoshinorim/quickstack/issues/5)
RUN sed -i '1i#define PACKAGE_VERSION 1' /usr/include/bfd.h \
	&& sed -i '1i#define PACKAGE 1' /usr/include/bfd.h
	
# build nucleus
RUN cd /service/nucleus \
    && make

# build cfg
RUN go build cfg.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["./cfg", "--config=service.conf"]
