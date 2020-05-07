#!/bin/bash

if [ ! -d ".git" ]; then
	echo "Not a git repo, not regenerating version info"
	exit 0
fi

EXTRA_VERSION=""

if [ "$#" -ne 1 -a "$#" -ne 2 ]; then
	echo "Usage: $0 TRANS_DEST [extra-version]"
	exit 1
else
	OUTPATH=$1/drbd
	if [ "$#" -eq 2 ]; then
		EXTRA_VERSION=$2
		echo "Adding $EXTRA_VERSION to git hashes"
	fi
fi

VERSION=$(date +%Y,%m,%d,%H)
DATE=$(date)
GITHASH=$(git describe --tags --always)$EXTRA_VERSION
DRBD_GITHASH="$(cd drbd ; git describe --tags --always)"$EXTRA_VERSION

VER_INTERNALNAME_STR="WinDRBD"
VER_FILEVERSION_STR="${GITHASH}\\0"

mkdir -p ${OUTPATH} || exit 1

## resource.rc
cat <<EOF > ${OUTPATH}/resource.rc
#define VER_FILEVERSION		${VERSION}
#define VER_FILEVERSION_STR	"${VER_FILEVERSION_STR}"
#define VER_PRODUCTVERSION	VER_FILEVERSION
#define VER_PRODUCTVERSION_STR	VER_FILEVERSION_STR

#define VER_COMPANYNAME_STR	 	"LINBIT"
#define VER_FILEDESCRIPTION_STR		"TODO"
#define VER_INTERNALNAME_STR		"${VER_INTERNALNAME_STR}"
#define VER_LEGALCOPYRIGHT_STR		"TODO"
#define VER_LEGALTRADEMARKS1_STR	"TODO"
#define VER_LEGALTRADEMARKS2_STR	"TODO"
#define VER_ORIGINALFILENAME_STR	"TODO"
#define VER_PRODUCTNAME_STR		VER_INTERNALNAME_STR

1 VERSIONINFO
FILEVERSION    	VER_FILEVERSION
PRODUCTVERSION 	VER_PRODUCTVERSION
//These need #include <windows.h>, enable them when integrated into buildsystem
FILETYPE	3	// VFT_DRV
FILESUBTYPE	7	// VFT2_DRV_SYSTEM
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904E4"
        BEGIN
            VALUE "CompanyName",      VER_COMPANYNAME_STR
            VALUE "FileDescription",  VER_FILEDESCRIPTION_STR
            VALUE "FileVersion",      VER_FILEVERSION_STR
            VALUE "InternalName",     VER_INTERNALNAME_STR
            VALUE "LegalCopyright",   VER_LEGALCOPYRIGHT_STR
            VALUE "LegalTrademarks1", VER_LEGALTRADEMARKS1_STR
            VALUE "LegalTrademarks2", VER_LEGALTRADEMARKS2_STR
            VALUE "OriginalFilename", VER_ORIGINALFILENAME_STR
            VALUE "ProductName",      VER_PRODUCTNAME_STR
            VALUE "ProductVersion",   VER_PRODUCTVERSION_STR
        END
    END
END
EOF

## drbd_buildtag.c
echo "const char *drbd_buildtag(void){return \"${GITHASH}\";}" > ${OUTPATH}/drbd_buildtag.c

## windrbd_version.h
echo "#ifndef __WINDRBD_VERSION_H" > ${OUTPATH}/windrbd_version.h
echo "#define __WINDRBD_VERSION_H" >> ${OUTPATH}/windrbd_version.h
echo "#define WINDRBD_VERSION \"${GITHASH}\"" >> ${OUTPATH}/windrbd_version.h
echo "#endif" >> ${OUTPATH}/windrbd_version.h

## windrbd.inf
sed "s#^DriverVer.*#DriverVer = $(date +%m/%d/%Y),0.10.7.0 ;Replaced by build magic#" ./windrbd/windrbd.inf.in > ${OUTPATH}/windrbd.inf

## inno-setup version include file
echo \#define MyAppVersion \"${GITHASH}\" > inno-setup/version.iss
