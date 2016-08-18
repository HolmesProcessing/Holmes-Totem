FROM ubuntu:14.04

# install what you need here
RUN apt-get update && apt-get install -y \
		python-pip \
		build-essential \
		python-dev \
		git \
	&& rm -rf /var/lib/apt/lists/*

RUN pip install tornado pefile bitstring

# get holmeslibrary
RUN mkdir -p /service
WORKDIR /service
RUN git clone https://github.com/HolmesProcessing/Holmes-Totem-Service-Library.git holmeslibrary
WORKDIR /service/holmeslibrary
RUN git fetch origin && git checkout 481280325e5e65ca6b83337f678537f22be834cc

# add the files to the container
ADD service.conf /service
ADD LICENSE /service
ADD README.md /service
ADD peinfo.py /service

# change the working directory
WORKDIR /service

CMD ["python2", "/service/peinfo.py"]
