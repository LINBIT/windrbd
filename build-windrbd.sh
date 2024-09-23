# This script copies the WinDRBD sources (and build artifacts)
# to machines capable of building it and finally uploads the
# installer to nexus. It works only in the Linbit environment.
# If you are looking for something with a sane Linux-only
# build process, take a look at WinDRBD 1.2.
#

set -e
echo "Creating tarball this may take a while ..."
tar zcf windrbd-initial.tarball.tar.gz --exclude=\*.tarball.tar.gz --exclude=inno-setup/install-windrbd\*.exe --exclude=converted-sources .
scp windrbd-initial.tarball.tar.gz johannes@10.43.224.39:/tmp
echo "Ok, now running Linux build steps (cocci, ...)"
ssh johannes@10.43.224.39 "rm -rf /tmp/build-windrbd
mkdir -p /tmp/build-windrbd
cd /tmp/build-windrbd
tar zxf ../windrbd-initial.tarball.tar.gz
make clean
make V=1
echo 'Creating tarball with Linux build artifacts ...'
tar zcf windrbd-built-converted-sources.tarball.tar.gz --exclude=\*.tarball.tar.gz --exclude=inno-setup/install-windrbd\*.exe .
echo Done
"
echo "Copying the result to Windows VM"
scp johannes@10.43.224.39:/tmp/build-windrbd/windrbd-built-converted-sources.tarball.tar.gz Administrator@10.43.224.35:/tmp

echo "Now running Windows build steps (compile, package, upload to nexus)"

ssh Administrator@10.43.224.35 "rm -rf /tmp/build-windrbd
mkdir -p /tmp/build-windrbd
cd /tmp/build-windrbd
tar zxf ../windrbd-built-converted-sources.tarball.tar.gz
export BUILD_ENV=jt-gitlab
export PATH=\$PATH:'/cygdrive/c/Program Files (x86)/Inno Setup 5/'
make clean
make package VERSION=gitlab
for i in inno-setup/install-windrbd-*.exe
do
	echo copiing \$i to linux host ...
	scp \$i johannes@10.43.224.39:/tmp/build-windrbd/\$i
done
echo Done
"

ssh johannes@10.43.224.39 "cd /tmp/build-windrbd
for i in inno-setup/install-windrbd-*.exe
do
	echo copiing \$i to nexus ...
	curl -f --netrc-file /etc/nexus-password --upload-file \$i https://nexus.at.linbit.com/repository/windows/WinDRBD/install-windrbd-latest-from-gitlab.exe
done
"

echo "Should be finished, resulting installer should be on nexus"
echo "To download do a"
echo "curl -O https://nexus.at.linbit.com/repository/windows/WinDRBD/install-windrbd-latest-from-gitlab.exe"
echo "drbdadm --version should show the correct version"
