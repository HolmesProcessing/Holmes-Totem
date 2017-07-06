FROM python:alpine

# add tornado
RUN pip3 install tornado

# create folder
RUN mkdir -p /service
WORKDIR /service

# get go dependencies
#RUN apk add --no-cache \
#		git \
    #&& git clone https://github.com/erocarrera/pefile.git \
    #&& rm -rf /var/cache/apk/*

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY peinfov2.py /service
COPY ordlookup /service/ordlookup
COPY peutils.py /service
COPY pefile.py /service
# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["python3", "peinfov2.py"]
