FROM python:alpine

# add tornado
RUN pip3 install tornado
RUN pip3 install pefile

# create folder
RUN mkdir -p /service
WORKDIR /service

###
# richheader specific options
###

# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY richlibrary.py /service
COPY richfuncfinder.py /service
COPY rich.py /service
COPY prodids.py /service
COPY ./signatures /service
# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf

CMD ["python3", "rich.py"]
