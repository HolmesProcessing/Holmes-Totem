FROM ubuntu:14.04

# install what you need here
RUN apt-get update
RUN apt-get install -y --fix-missing python3-pip wget build-essential checkinstall dh-autoreconf libssl-dev libmagic-dev python-dev


# install python3 dependencies
RUN pip3 install requests tornado


# build yara from source
RUN mkdir /yara
WORKDIR /yara
RUN wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
RUN tar -zxf v3.4.0.tar.gz
WORKDIR /yara/yara-3.4.0
RUN ./bootstrap.sh
RUN ./configure --with-crypto --enable-magic
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
ADD peid_worker.py /service
ADD rulepack /service/rulepack


# gather the rules and add them
ADD rules.yar /service
WORKDIR /service
RUN python3 getrules.py


# create a new user with limited access
RUN useradd -s /bin/bash service
RUN chown -R service /service


USER service


CMD ["python3", "/service/peid_worker.py", "/service/rules.yar"]
