FROM ubuntu:jammy

# prevent tzdata from stalling the installation
ENV DEBIAN_FRONTEND=noninteractive
ENV WINEDEBUG=-all
ENV WINEPREFIX=/wine

RUN apt-get update
RUN apt-get install --no-install-recommends -y ca-certificates wget apt-utils make git iputils-ping python3 rsync vim xz-utils unzip ssh curl osslsigncode

RUN dpkg --add-architecture i386
RUN mkdir -pm755 /etc/apt/keyrings
RUN wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
RUN wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/bionic/winehq-bionic.sources

RUN apt-get update
RUN apt-get install --no-install-recommends -y winehq-stable

# build default wine dir
RUN wineboot -i

COPY ["Inno Setup 5", "/wine/drive_c/Program Files (x86)/Inno Setup 5/"]
# Wine Mono from https://dl.winehq.org/wine/wine-mono/7.4.0/
# RUN mkdir -p /wine/drive_c/windows/mono
# COPY ["wine-mono-7.4.0-x86.tar.xz", "/wine/drive_c/windows/mono/wine-mono-7.4.0-x86.tar.xz"]
# RUN cd /wine/drive_c/windows/mono && tar Jxf wine-mono-7.4.0-x86.tar.xz
# RUN mv /wine/drive_c/windows/mono/wine-mono-7.4.0 /wine/drive_c/windows/mono/mono-2.0
# COPY ["Microsoft Visual Studio", "/wine/drive_c/Program Files/Microsoft Visual Studio/"]

