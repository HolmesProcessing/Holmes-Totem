FROM ubuntu:14.04

# install what you need here
RUN apt-get update
RUN apt-get install -y --fix-missing python-pip build-essential python-dev
RUN pip install tornado
RUN apt-get install -y --fix-missing git

# add the files to the container
RUN mkdir -p /service
WORKDIR /service
RUN git clone https://github.com/HolmesProcessing/Holmes-Totem-Service-Library.git library
WORKDIR /service/library
# to overcome the caching issue, the correct revision must go here
RUN git fetch origin && git checkout 1c196c89d08644a71cbf4d9720ce156b8ab1cf5e

ADD LICENSE README.md service.meta /service/
ADD zipmeta.py ZipParser.py extra_field_parse.py /service/

# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service

USER service
WORKDIR /service
CMD ["python2", "/service/zipmeta.py"]
