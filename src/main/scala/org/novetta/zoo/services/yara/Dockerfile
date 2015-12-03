FROM ubuntu:14.04

# install what you need here
RUN apt-get update
RUN apt-get install -y --fix-missing yara python3-yara python3-pip

RUN pip3 install requests tornado

# add the core files to the container
RUN mkdir -p /service
ADD getrules.py /service
ADD service.conf /service
ADD yara_worker.py /service

# gather the rules and add them
ADD rules.yar /service
WORKDIR /service
RUN ["python3", "getrules.py"]

# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service

USER service
EXPOSE 7701

CMD ["python3", "/service/yara_worker.py", "/service/rules.yar"]

#####
# RUNNING THIS CONTAINER:
# Since this container need to have access to
# the sample files your need to run this
# contiainer with:
# -v /tmp:/tmp:ro
# This allow the container to access /tmp
# on the local file system in real-only mode.
