FROM python:alpine

# add tornado
RUN pip3 install tornado

# create folder
RUN mkdir -p /service
WORKDIR /service

###
# dnsmeta specific options
###

# add dependencies for asnmeta
RUN pip3 install dnspython

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY gatherdns.py /service
COPY dnsmeta.py /service
# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["python3", "dnsmeta.py"]
