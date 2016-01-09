FROM golang

# Get Go dependencies
RUN go get github.com/julienschmidt/httprouter

# Setup service
RUN mkdir -p /service
ADD . /service

WORKDIR /service
RUN go build -o vtsample

ENTRYPOINT ["/service/vtsample", "-config=/service/service.conf"] 
