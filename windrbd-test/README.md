Test suite for WinDRBD
======================

This is a google test based test suite that calls various
WIN32 API calls to test the functionality and stability
of WinDRBD.

This is tested only for CygWin under Windows 7.

You need to have google test installed (expected in 
/usr/local/lib, but you can also edit the Makefile to
change that). To do so go 

git clone git@github.com:google/googletest.git
cd googletest
cmake
make
(make install does not work for me, copy libs and headers 
manually or edit Makefile)

To run the test do a

make test DRIVE=H:

Where H: is the DRBD drive (only exists in Linbit's WinDRBD
version, not in ManTech's)

