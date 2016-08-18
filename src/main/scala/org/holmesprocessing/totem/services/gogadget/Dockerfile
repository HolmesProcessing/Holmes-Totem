FROM golang:latest

# Install ropgadget if not yet installed.
RUN apt-get update && apt-get install -y \
		python-pip \
		build-essential \
		python-dev \
	&& rm -rf /var/lib/apt/lists/*


RUN pip install capstone
RUN pip install ropgadget

# Add relevant files to the container.
RUN mkdir -p /service
ADD service.conf /service
ADD LICENSE /service
ADD README.md /service
ADD gogadget.go /service

# Change the working directory.
WORKDIR /service

# Build gogadget.
RUN go get "github.com/go-ini/ini"
RUN go get "github.com/julienschmidt/httprouter"
RUN go build gogadget.go

CMD ["/service/gogadget", "--config=service.conf"]
