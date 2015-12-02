FROM ubuntu:14.04

# install what you need here
RUN apt-get update
RUN apt-get install -y --fix-missing yara
RUN pip install yara-python

# add the files to the container
RUN mkdir -p /service
ADD yara.py /service
ADD rules.yar /service

# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service

USER service
WORKDIR /service

EXPOSE 7701
CMD ["python2", "/service/yara.py", "/service/rules.yar"]