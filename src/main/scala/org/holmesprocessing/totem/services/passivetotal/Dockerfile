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
# passivetotal specific options
###

# get additional dependencies
RUN go get "github.com/go-ini/ini" \
    && go get "github.com/antonholmquist/jason"

# create directory to hold sources for compilation
RUN mkdir -p src/passivetotal-service

# add files to the container
# sources files to to GOPATH instead of /service for compilation
COPY LICENSE /service
COPY README.md /service
COPY src/passivetotal-service $GOPATH/src/passivetotal-service
ARG conf=service.conf
ADD $conf /service/service.conf

# download TLD list from iana.org
RUN wget -O TLDList.txt "http://data.iana.org/TLD/tlds-alpha-by-domain.txt"

# build service's packages
# build service
# copy service binary to /service
RUN cd $GOPATH/src/passivetotal-service \
    && go build \
    && cp passivetotal-service /service/passivetotal-service

# clean up git
# clean up behind the service build
# clean up golang as we don't need it anymore
RUN apk del --purge \
        git \
    && rm -rf /var/cache/apk/* \
    && rm -rf $GOPATH \
    && rm -rf /usr/local/go

CMD ["./passivetotal-service", "-config=service.conf"]
