= Building WinDRBD with mingw-w64 toolchain

Starting from the 1.2 branch WinDRBD is built with
gcc (mingw-w64). Building with Microsoft Visual
C does not work any more.

This guide assumes you want to build for a modern
Windows Server (2016 or later) and the x86_64 
(64 bit) architecture.

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


