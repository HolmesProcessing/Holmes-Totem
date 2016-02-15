FROM ubuntu:14.04

# install what you need here
RUN apt-get update
RUN apt-get install -y --fix-missing python-pip build-essential python-dev git
RUN pip install tornado pefile bitstring

# get holmeslibrary
RUN mkdir -p /service
WORKDIR /service
RUN git clone https://github.com/HolmesProcessing/Holmes-Totem-Service-Library.git holmeslibrary
WORKDIR /service/holmeslibrary
RUN git fetch origin && git checkout 481280325e5e65ca6b83337f678537f22be834cc

# add the files to the container
ADD peinfo.py /service

# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service

USER service
WORKDIR /service

CMD ["python2", "/service/peinfo.py"]
