FROM golang:1.6.2

# Install ropgadget if not yet installed.
RUN apt-get update && apt-get install -y --force-yes --fix-missing python-pip build-essential python-dev
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
