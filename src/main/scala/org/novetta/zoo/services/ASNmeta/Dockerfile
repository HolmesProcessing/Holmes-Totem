FROM ubuntu:14.04

# install what you need here
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y --fix-missing python3-pip


# install python3 dependencies
RUN pip3 install tornado dnspython3


# add the files to the container
RUN mkdir -p /service
ADD gatherasn.py /service
ADD asnmeta.py /service
ADD service.conf /service


# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service


USER service
WORKDIR /service


EXPOSE 7730
CMD ["python3", "/service/asnmeta.py"]
