# Cannot build angr from python:2.7-alpine
FROM python:2.7

# add tornado
RUN pip2 install tornado

# create folder
RUN mkdir -p /service
WORKDIR /service

# add holmeslibrary
RUN wget https://github.com/HolmesProcessing/Holmes-Totem-Service-Library/archive/v0.1.tar.gz \
	&& tar xf v0.1.tar.gz \
	&& mv Holmes-Totem-Service* holmeslibrary \
	&& rm -rf /var/cache/apk/* v0.1.tar.gz

###
# cfgangr specific options
###

# add dependencies for cfgangr
RUN pip2 install angr angr-utils networkx


# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY cfgangr.py /service
COPY convertbinary.py /service


# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf
CMD ["python2", "cfgangr.py"]

