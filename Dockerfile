# docker build -t libdft-image:latest .
# docker run -it --rm -v "$(realpath ./):/libdft" --cap-add=SYS_PTRACE --name libdft-dev libdft-image:latest

FROM --platform=linux/amd64 ubuntu:20.04

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install --no-install-recommends \
        apt-utils \
        build-essential \
        gcc-multilib \
        g++-multilib \
        gdb \
        git \
        vim \
        file \
        wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# pin tool
ENV PIN_TAR_NAME="pin-3.20-98437-gf02b61307-gcc-linux"
ENV PIN_INSTALL_DIR="/opt/pin"
ENV PIN_ROOT="${PIN_INSTALL_DIR}/${PIN_TAR_NAME}"

# install pin tool
RUN mkdir -p ${PIN_INSTALL_DIR} && \
    echo "downloading pin tool: ${PIN_TAR_NAME}.tar.gz" && \
    wget -O /tmp/${PIN_TAR_NAME}.tar.gz --no-check-certificate "https://software.intel.com/sites/landingpage/pintool/downloads/${PIN_TAR_NAME}.tar.gz" && \
    echo "extracting pin tool to ${PIN_INSTALL_DIR}" && \
    tar xzf /tmp/${PIN_TAR_NAME}.tar.gz -C ${PIN_INSTALL_DIR} && \
    rm /tmp/${PIN_TAR_NAME}.tar.gz && \
    echo "pin tool installed at ${PIN_ROOT}"

# export pin path
ENV PATH="${PIN_ROOT}:${PATH}"

RUN mkdir -p /libdft
WORKDIR libdft

COPY ./env.init /opt/

ENTRYPOINT [ "/opt/env.init" ]
CMD ["/bin/bash"]
# CMD ["sleep", "infinity"]
