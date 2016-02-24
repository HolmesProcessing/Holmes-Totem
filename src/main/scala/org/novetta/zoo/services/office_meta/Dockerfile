FROM ubuntu:14.04

# install what you need here
RUN apt-get update
RUN apt-get install -y --fix-missing python-pip build-essential python-dev git
RUN pip install tornado

# add the files to the container
RUN mkdir -p /service
WORKDIR /service
RUN git clone https://github.com/HolmesProcessing/Holmes-Totem-Service-Library.git library
WORKDIR /service/library
# to overcome the caching issue, the correct revision must go here
RUN git fetch origin && git checkout 7832ab6b0d4d097c4aa3c309d6fc6335236cd0bb

ADD LICENSE README.md service.conf /service/
ADD service.py office_meta.py /service/

# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service

USER service
WORKDIR /service
CMD ["python2", "/service/service.py"]
