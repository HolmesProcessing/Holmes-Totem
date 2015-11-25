FROM golang

ADD . /go/src/github.com/cynexit/Holmes-Totem-Service-VTSample

RUN go get github.com/julienschmidt/httprouter
RUN go install github.com/cynexit/Holmes-Totem-Service-VTSample

ENTRYPOINT /go/bin/Holmes-Totem-Service-VTSample

EXPOSE 7710
