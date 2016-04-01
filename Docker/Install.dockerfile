# --------------------------------------- #
# Oracle Java 8 installation taken from
# https://github.com/dockerfile/java
# https://github.com/dockerfile/java/tree/master/oracle-java8

FROM ubuntu
RUN apt-get install -y software-properties-common
RUN \
    echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | debconf-set-selections && \
    add-apt-repository -y ppa:webupd8team/java && \
    apt-get update && \
    apt-get install -y oracle-java8-installer && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/oracle-jdk8-installer
ENV JAVA_HOME /usr/lib/jvm/java-8-oracle
# --------------------------------------- #

# enable https for apt
RUN apt-get update && apt-get install -y apt-transport-https

# install rabbitmq
RUN echo "deb http://www.rabbitmq.com/debian/ testing main" | tee -a /etc/apt/sources.list.d/rabbitmq.list
RUN wget https://www.rabbitmq.com/rabbitmq-signing-key-public.asc
RUN apt-key add rabbitmq-signing-key-public.asc
RUN apt-get update && apt-get install -y rabbitmq-server

# install scala sbt
RUN echo "deb https://dl.bintray.com/sbt/debian /" | tee -a /etc/apt/sources.list.d/sbt.list
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 642AC823
RUN apt-get update
RUN apt-get install -y sbt

# setup Holmes-Totem
RUN apt-get install -y git
RUN mkdir -p /data
WORKDIR /data
RUN git clone INSTALL_REPOSITORY
WORKDIR /data/Holmes-Totem
RUN sbt assembly

# start totem
CMD service rabbitmq-server start && java -jar /data/Holmes-Totem/target/scala-2.11/totem-assembly-1.0.jar /data/Holmes-Totem/config/totem.conf
