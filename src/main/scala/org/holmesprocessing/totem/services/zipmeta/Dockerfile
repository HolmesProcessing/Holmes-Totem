FROM python:alpine

# add tornado
RUN pip3 install tornado

# create folder
RUN mkdir -p /service
WORKDIR /service

###
# zipmeta specific options
###

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY ZipParser.py /service
COPY extra_field_parse.py /service
COPY zipmeta.py /service
COPY holmeslibrary /service/holmeslibrary
# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["python3", "/service/zipmeta.py"]
