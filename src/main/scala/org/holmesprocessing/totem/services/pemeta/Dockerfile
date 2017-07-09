FROM golang:alpine

# Create folder
RUN mkdir -p /service
WORKDIR /service

# Get Golang dependencies
RUN apk add --no-cache \
        git \
        && go get github.com/julienschmidt/httprouter \
        && rm -rf /var/cache/apk/*

# Get PEV dependencies
RUN apk add --no-cache \
        bash \
        build-base \
        openssl-dev \
	    make \
        && git clone -b testing https://github.com/boddumanohar/libpe.git \
        && rm -rf /var/cache/apk/*

# Clean Up
RUN apk del --purge \
        #build-base \
        git 

# Set environment variables.
ENV CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2"

# Making quick changes. REMOVING PRAGMA VALUES FOR THE SAKE OF GETTING OPTIONAL HEADERS.
RUN sed -i 's/.*pack(push, 1).*//g' /service/libpe/hdr_optional.h
RUN sed -i 's/.*pack(pop).*//g' /service/libpe/hdr_optional.h

# Installing Libpe (- PEV's library)
RUN cd /service/libpe \
	&& make \
	&& make install
# add Service files to the container.

COPY LICENSE /service
COPY README.md /service
COPY pemeta.go /service
RUN go build pemeta.go

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf


CMD ["./pemeta", "--config=service.conf"]
