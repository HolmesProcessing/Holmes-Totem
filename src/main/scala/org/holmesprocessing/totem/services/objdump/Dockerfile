FROM golang:latest

# Install objdump if not yet installed.
RUN apt-get update && apt-get install -y \
		binutils \
	&& rm -rf /var/lib/apt/lists/*

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
