FROM ubuntu:14.04

# install what you need here
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y python-pip
RUN pip install tornado

# add the files to the container
RUN mkdir -p /service
ADD zipmeta.py /service
ADD ZipParser.py /service
ADD extra_field_parse.py /service

# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service

USER service
WORKDIR /service

EXPOSE 7715
CMD python2 /service/zipmeta.py

#####
#
# If run locally and needs to access /tmp, run this container with:
# -v /tmp:/tmp:ro
#
# Example:
# docker build -t zipmeta .
# docker run -p 7715:7715 -v /tmp:/tmp:ro zipmeta:latest
#
