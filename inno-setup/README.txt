This directory contains packaging information for the Windows installer
and uninstaller of WinDRBD. It was added with version windrbd-0.8.9.

We are using inno-setup (http://www.jrsoftware.org) which perfectly
fits our needs (thanks to the authors Jordan Russell and Martijn Laan!)
and saved a lot of work.

To obtain inno-setup go to their website, install it (sorry only runs
under Microsoft Windows platforms) and make sure the application
directory is in the PATH (we need to call the iscc command line
compiler to generate the .EXE).

