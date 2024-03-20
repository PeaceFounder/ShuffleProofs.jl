FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install --yes m4 cpp gcc make libtool automake autoconf libgmp-dev xterm openjdk-11-jdk wget sudo && \
    wget https://www.verificatum.org/files/verificatum-vmn-3.0.4-full.tar.gz  && \
    tar xvfz verificatum-vmn-3.0.4-full.tar.gz && \
    cd verificatum-vmn-3.0.4-full && \
    sudo make install 
