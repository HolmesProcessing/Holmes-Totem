FROM ubuntu:14.04

# install what you need here
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y --fix-missing python3-pip wget build-essential checkinstall dh-autoreconf libssl-dev


# install python3 dependencies
RUN pip3 install requests tornado


# build yara from source
RUN mkdir /yara
WORKDIR /yara
RUN wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
RUN tar -zxf v3.4.0.tar.gz
WORKDIR /yara/yara-3.4.0
RUN ./bootstrap.sh
RUN ./configure --with-crypto
RUN make
RUN make install


# build yara-python from source
WORKDIR /yara/yara-3.4.0/yara-python
RUN python3 setup.py build
RUN python3 setup.py install


# yaras ubuntu fix
RUN echo "/usr/local/lib" >> /etc/ld.so.conf
RUN ldconfig


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
