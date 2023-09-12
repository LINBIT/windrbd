# Building WinDRBD under Linux

Starting from the 1.2 branch WinDRBD is built with
gcc (mingw-w64). Building with Microsoft Visual
C does not work any more.

There are two ways of building WinDRBD: the
hard way (setting up the build environment
on the Linux host machine) and the quick way
(using a docker container to build WinDRBD).

In this file we will show the quick way first
because this is probably what you want to go
for.

## TODO: xxx

    docker pull quay.io/johannesthoma/windrbd-devenv

## Building WinDRBD using a docker container

First if you haven't done so, install docker:

    sudo apt install docker.io

Then build the build environment (this requires
an internet connection as well as many CPU cores
since we're building one of the C compilers
therein):

    make docker

This process takes about 10-30 minutes depending
on your hardware.

Finally use the newly created docker image (Ubuntu
22.04 based) to build WinDRBD (working directory
must be the windrbd root directory):

    make package-in-docker

It should take a few minutes to build WinDRBD
(including drbd-utils and the generate-cat-file
build tool).

## Prepare a Linux host for building WinDRBD

This guide assumes you want to build for a modern
Windows Server (2016 or later) and the x86\_64\_
(64 bit) architecture. It further assumes that
you are running Ubuntu 22.04 Jammy as the build
machine (not strictly required but that is what
we have in our build environment). Since we are
importing Fedora packages, Fedora itself also
might be a good choice.

### Installing build dependencies

#### mingw64 cross compiler

To install mingw-w64 use the mingw-w64-build script
as shown below:

	git clone https://github.com/Zeranoe/mingw-w64-build.git
	cd mingw-w64-build
	./mingw-w64-build x86_64

This will install mingw-w64 into your home directory
in

	/home/$USER/.zeranoe/mingw-w64

This is also where the mingw Makefile in WinDRBD expects
to find the compiler and linker.

Depending on the speed of your machine the process takes
5 to 20 minutes.

You might have to install additional packages like texinfo
(for makeinfo) but the script will tell you what to do.

#### generate-cat-file

generate-cat-file is a small C program that generates
the Microsoft Security Catalog (.cat) files which are
needed when a driver is added to the driver store.

It is an OpenSource replacement for inf2cat.exe
(and makecat.exe) of the Windows EWDK that does not
depend on the wintrust.dll library. Therefore it
runs everywhere a C99 compiler is available.

generate-cat-file is a submodule of the WinDRBD
repo and should be already checked out if you
cloned the WinDRBD repository with --recursive.
It also should be build automatically by the
WinDRBD makefile. So bottom line is nothing to
do here.

#### osslsigncode

To sign the windrbd.sys and the security catalog (windrbd.cat)
file you need osslsigncode. Install it with

	apt install osslsigncode

Note that the osslsigncode before Ubuntu 22.04 cannot sign
catfiles, so you either have to compile osslsigncode on your
own or use a more modern Linux distro.

#### wine

In order to create an installable package the inno-setup
Windows program is required. It is still 32-bit which means
that we need a 32 bit wine (TODO: really?). The inno setup
program itself is part of the WinDRBD repository because
else a Windows / wine installation would be required to
build the docker image.

On Ubuntu (and Debian) one needs to add the i386 architecture:

    dpkg --add-architecture i386

Then install the latest Wine from the winehq with following
commands:

    mkdir -pm755 /etc/apt/keyrings
    wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
    wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/bionic/winehq-bionic.sources
    apt-get update
    apt-get install --no-install-recommends -y winehq-stable
    wineboot -i

#### cygwin cross compiler

Building the cross compiler for cygwin (to generate cygwin
binaries on Linux) is currently not working but there are
Fedora packages pre-built which you may use. You can use
the alien command to convert the rpm files to deb files.

This should change once I find out how to cross compile
the cygwin compiler (which is needed to build drbd-utils)

To obtain, convert and post process the cygwin compiler
you can use the following commands:

    wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/05198422-cygwin-binutils/cygwin-binutils-generic-2.39-3.fc36.x86_64.rpm
    wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/02898776-cygwin-gcc/cygwin64-gcc-11.2.0-2.fc36.x86_64.rpm
    wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/02898776-cygwin-gcc/cygwin64-cpp-11.2.0-2.fc36.x86_64.rpm
    wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/02898776-cygwin-gcc/cygwin-gcc-common-11.2.0-2.fc36.x86_64.rpm
    wget https://rpmfind.net/linux/opensuse/distribution/leap/15.2/repo/oss/x86_64/libisl15-0.18-lp152.3.114.x86_64.rpm
    wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/03136948-cygwin/cygwin64-3.3.3-1.fc36.noarch.rpm
    wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/05198422-cygwin-binutils/cygwin64-binutils-2.39-3.fc36.x86_64.rpm
    wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/04344696-cygwin-w32api-runtime/cygwin64-w32api-runtime-10.0.0-1.fc36.noarch.rpm
    wget https://download.copr.fedorainfracloud.org/results/yselkowitz/cygwin/fedora-36-x86_64/04344613-cygwin-w32api-headers/cygwin64-w32api-headers-10.0.0-1.fc36.noarch.rpm

    alien -d *.rpm
    dpkg -i *.deb

    cp /usr/lib64/libisl.so.15.3.0 /usr/lib/x86_64-linux-gnu
    cp /usr/lib64/libisl.so.15 /usr/lib/x86_64-linux-gnu

### Building WinDRBD

You should end up now with a Linux host that can compile
WinDRBD solely with OpenSource tools. To compile do:

    make all

To generate a installable package do

    make package

The result is an install-windrbd-\<version\>.exe which can
be run on a Windows machine. Note that this file is not
officially signed (you need a signature from Microsoft)
so you have to put your Windows machine into test mode:

    bcdedit /set TESTSIGNING ON

and reboot the target Windows node.

## Summary

We highly recommend to use the pre-built docker image
to build WinDRBD on Linux. Alternatively you can create
your own docker image or if you have enough reasons to
do so install the build dependencies on your Linux host.

If you have questions about WinDRBD, the build process
or want to obtain binary packages which are signed
by Microsoft please contact [LINBIT](https://www.linbit.com).
By subscribing to a support contract you help LINBIT
to keep supporting the WinDRBD project and keep it
Open Source.

Happy Hacking,

 \- Johannes
