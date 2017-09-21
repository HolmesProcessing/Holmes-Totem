# Cannot build angr from python:2.7-alpine
FROM python:2.7

# add tornado
RUN pip2 install tornado

# create folder
RUN mkdir -p /service
WORKDIR /service

###
# cfgangr specific options
###

# add dependencies for cfgangr
RUN pip2 install angr networkx==1.11 simuvex
RUN pip2 install -I --no-use-wheel capstone


# add the files to the container
COPY LICENSE /service
COPY README.md /service
COPY cfgangr.py /service
COPY convertbinary.py /service


# add the configuration file (possibly from a storage uri)
ARG conf=service.conf
ADD $conf /service/service.conf
CMD ["python2", "cfgangr.py"]

