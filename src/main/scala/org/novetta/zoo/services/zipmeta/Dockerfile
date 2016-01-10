FROM ubuntu:14.04

# install what you need here
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y --fix-missing python-pip build-essential
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

CMD ["python2", "/service/zipmeta.py"]
