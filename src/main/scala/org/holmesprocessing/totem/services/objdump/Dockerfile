FROM golang:1.6.2

# Install objdump if not yet installed.
RUN apt-get update && apt-get install -y --force-yes --fix-missing binutils

# Add relevant files to the container.
RUN mkdir -p /service
ADD service.conf /service
ADD LICENSE /service
ADD README.md /service
ADD objdump.go /service

# Change the working directory.
WORKDIR /service

# Build Objdump.
RUN go get "github.com/go-ini/ini"
RUN go get "github.com/julienschmidt/httprouter"
RUN go build objdump.go

CMD ["/service/objdump", "--config=service.conf"]
