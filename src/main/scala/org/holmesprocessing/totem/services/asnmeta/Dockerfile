FROM python:alpine

# add tornado
RUN pip3 install tornado

# create folder
RUN mkdir -p /service
WORKDIR /service

# add holmeslibrary
RUN apk add --no-cache \
		wget \
	&& wget https://github.com/HolmesProcessing/Holmes-Totem-Service-Library/archive/v0.1.tar.gz \
	&& tar xf v0.1.tar.gz \
	&& mv Holmes-Totem-Service* holmeslibrary \
	&& rm -rf /var/cache/apk/* v0.1.tar.gz

###
# asnmeta specific options
###

# add dependencies for asnmeta
RUN pip install dnspython3

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY gatherasn.py /service
COPY asnmeta.py /service
# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["python3", "asnmeta.py"]
