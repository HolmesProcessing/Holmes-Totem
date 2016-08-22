FROM python:2-alpine

# add tornado
RUN pip install tornado

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
# zipmeta specific options
###

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY ZipParser.py /service
COPY extra_field_parse.py /service
COPY zipmeta.py /service

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["python2", "/service/zipmeta.py"]
