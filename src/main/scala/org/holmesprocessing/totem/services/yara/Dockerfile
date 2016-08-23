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
# yara specific options
###

# get dependencies
RUN apk add --no-cache \
		autoconf \
		automake \
		build-base \
		file \
		file-dev \
		libtool \
		libmagic \
		openssl-dev \
	&& wget https://github.com/VirusTotal/yara/archive/v3.5.0.tar.gz \
	&& tar xf v3.5.0.tar.gz \
	&& rm -rf /var/cache/apk/* yara-3.5.0.tar.gz

# build yara
WORKDIR /service/yara-3.5.0
RUN	./bootstrap.sh \
	&& ./configure \
		--with-crypto \
		--enable-magic \
	&& make \
	&& make install 
WORKDIR /service/

# build yara-python
RUN pip3 install yara-python requests

# clean up
RUN apk del --purge \
		autoconf \
		automake \
		build-base \
	&& rm -rf /var/cache/apk/* yara-3.5.0

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY getrules.py /service
COPY yara_worker.py /service

# gather the rules and add them
COPY rules.yar /service
RUN python3 getrules.py

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf
CMD ["python3", "yara_worker.py"]
