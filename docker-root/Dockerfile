FROM ubuntu:jammy

# prevent tzdata from stalling the installation
ENV DEBIAN_FRONTEND=noninteractive
ENV WINEDEBUG=-all
ENV WINEPREFIX=/wine

RUN apt-get update
RUN apt-get install --no-install-recommends -y ca-certificates wget apt-utils make git iputils-ping python3 rsync vim xz-utils unzip ssh curl osslsigncode g++ flex bison texinfo m4 bzip2 alien

RUN dpkg --add-architecture i386
RUN mkdir -pm755 /etc/apt/keyrings
RUN wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
RUN wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/bionic/winehq-bionic.sources

RUN apt-get update
RUN apt-get install --no-install-recommends -y winehq-stable

# build default wine dir
RUN wineboot -i

COPY ["Inno Setup 5", "/wine/drive_c/Program Files (x86)/Inno Setup 5/"]

RUN git clone https://github.com/Zeranoe/mingw-w64-build.git
RUN cd mingw-w64-build && ./mingw-w64-build x86_64
# Also for i686: uncomment this:
# RUN cd mingw-w64-build && ./mingw-w64-build i686

# We expect a bind mount to the WinDRBD project root in /windrbd
# Use -v /path/to/windrbd:/windrbd parameter to docker run
RUN git config --global --add safe.directory /windrbd
RUN git config --global --add safe.directory /windrbd/drbd-utils

# Now .. the cygwin cross compiler. There is a more or less
# maintained fedora binary (rpm's) which we convert with
# alien and hope that it installs
RUN wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/05198422-cygwin-binutils/cygwin-binutils-generic-2.39-3.fc36.x86_64.rpm
RUN wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/02898776-cygwin-gcc/cygwin64-gcc-11.2.0-2.fc36.x86_64.rpm
RUN wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/02898776-cygwin-gcc/cygwin64-cpp-11.2.0-2.fc36.x86_64.rpm
RUN wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/02898776-cygwin-gcc/cygwin-gcc-common-11.2.0-2.fc36.x86_64.rpm
RUN wget https://rpmfind.net/linux/opensuse/distribution/leap/15.2/repo/oss/x86_64/libisl15-0.18-lp152.3.114.x86_64.rpm
RUN wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/03136948-cygwin/cygwin64-3.3.3-1.fc36.noarch.rpm
RUN wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/05198422-cygwin-binutils/cygwin64-binutils-2.39-3.fc36.x86_64.rpm
RUN wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/04344696-cygwin-w32api-runtime/cygwin64-w32api-runtime-10.0.0-1.fc36.noarch.rpm
RUN wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/04344613-cygwin-w32api-headers/cygwin64-w32api-headers-10.0.0-1.fc36.noarch.rpm

RUN alien -d *.rpm
RUN dpkg -i *.deb

RUN cp /usr/lib64/libisl.so.15.3.0 /usr/lib/x86_64-linux-gnu
RUN cp /usr/lib64/libisl.so.15 /usr/lib/x86_64-linux-gnu
