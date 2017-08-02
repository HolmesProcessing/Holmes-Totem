FROM python:alpine

# add tornado
RUN pip3 install tornado

# create folder
RUN mkdir -p /service
WORKDIR /service

###
# peinfo v2 specific options
##

# add dependencies for peinfo v2
RUN pip3 install --upgrade pefile

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY peinfov2.py /service

# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["python3", "peinfov2.py"]
