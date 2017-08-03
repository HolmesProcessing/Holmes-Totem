FROM python:alpine

# add tornado
RUN pip3 install tornado

# create folder
RUN mkdir -p /service
WORKDIR /service

# add dependencies for asnmeta
RUN pip3 install dnspython

###
# ansmeta specific options
###

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY gatherasn.py /service
COPY asnmeta.py /service

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["python3", "asnmeta.py"]
