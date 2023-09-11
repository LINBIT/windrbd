# Building WinDRBD with mingw-w64 toolchain

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

## Building WinDRBD using a docker container

First if you haven't done so, install docker:

    # or yum, ...
    sudo apt install docker

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
Windows Server (2016 or later) and the x86_64 
(64 bit) architecture. It further assumes that
you are running Ubuntu 22.04 Jammy as the build
machine (not strictly required but that is what
we have in our build environment). Since we are
importing Fedora packages, Fedora itself also
might be a good choice.

== Installing build dependencies

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

To sign the windrbd.sys and the security catalog (windrbd.cat)
file you need osslsigncode. Install it with

	apt install osslsigncode

Note that the osslsigncode before Ubuntu 22.04 cannot sign
catfiles, so you either have to compile osslsigncode on your
own or use a more modern Linux distro.

unfinished ...
