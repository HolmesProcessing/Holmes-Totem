FROM ubuntu:14.04

# install what you need here
RUN apt-get update
RUN apt-get install -y --fix-missing yara
RUN pip install yara-python
RUN pip3 install requests

# add the core files to the container
RUN mkdir -p /service
ADD getrules.py /service
ADD service.conf /service
ADD yara.py /service

# gather the rules and add them
RUN ["python3", "getrules.py"]
ADD rules.yar /service

# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service

USER service
WORKDIR /service

EXPOSE 7701
CMD ["python2", "/service/yara.py", "/service/rules.yar"]