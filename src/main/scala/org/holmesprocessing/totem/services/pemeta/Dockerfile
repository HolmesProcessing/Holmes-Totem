FROM golang:alpine

# Create folder
RUN mkdir -p /service
WORKDIR /service

# Get Golang and PEV dependencies
RUN apk add --no-cache \
        git \
        && go get github.com/julienschmidt/httprouter \
        && git clone -b testing https://github.com/boddumanohar/libpe.git \
        && rm -rf /var/cache/apk/*

RUN apk add --no-cache \
        bash \
        build-base \
            openssl-dev \
	    make \
	    g++ \
        && rm -rf /var/cache/apk/*

# Clean Up
RUN apk del --purge \
        build-base \
        && rm -rf /var/cache/apk/* yara-3.5.0

# Set environment variables.
ENV CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2

# Installing Libpe
RUN cd /service/libpe \
	&& make \
	&& make install

# Making quick changes.
RUN sed -i 's/.*pe_optional.*/IMAGE_OPTIONAL_HEADER_64 *pe_optional(pe_ctx_t *ctx);/g' /service/libpe/pe.h

# add Service files to the container.

COPY LICENSE /service
COPY README.md /service
COPY pev.go /service
RUN go build pev.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf


CMD ["./pev", "--config=service.conf"]
