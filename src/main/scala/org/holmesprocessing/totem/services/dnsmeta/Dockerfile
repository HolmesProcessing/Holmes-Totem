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
# dnsmeta specific options
###

# add dependencies for asnmeta
RUN pip install dnspython3

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY gatherdns.py /service
COPY dnsmeta.py /service
COPY service.conf /service

CMD ["python3", "dnsmeta.py"]
