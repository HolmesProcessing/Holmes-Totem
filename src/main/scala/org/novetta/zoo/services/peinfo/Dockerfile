FROM ubuntu:14.04

# install what you need here
RUN apt-get update
RUN apt-get install -y python-pip
RUN pip install tornado pefile bitstring

# add the files to the container
RUN mkdir -p /service
ADD peinfo.py /service

# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service

USER service
WORKDIR /service

EXPOSE 7705
CMD ["python2", "/service/peinfo.py"]
