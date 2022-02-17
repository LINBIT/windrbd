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
PATCHLEVEL=$( echo $GITHASH | sed -e 's/.*-\([0-9]*\)-g.*/\1/g' )
if [ "${PATCHLEVEL:0:1}" == w ] ; then PATCHLEVEL=0 ; fi
WINDRBD_VERSION=$( echo $GITHASH | sed -e 's/^windrbd-\([0-9.]*\).*$/\1/g' ).$PATCHLEVEL
RESOURCE_VERSION=$( echo $WINDRBD_VERSION | tr . , )

echo Patchlevel is $PATCHLEVEL WinDRBD version is $WINDRBD_VERSION, Resource version is $RESOURCE_VERSION

VER_INTERNALNAME_STR="WinDRBD"
VER_FILEVERSION_STR="${GITHASH}\\0"

mkdir -p ${OUTPATH} || exit 1

## resource.rc
cat <<EOF > ${OUTPATH}/resource.rc
#define VER_FILEVERSION		${RESOURCE_VERSION}
#define VER_FILEVERSION_STR	"${VER_FILEVERSION_STR}"
#define VER_PRODUCTVERSION	VER_FILEVERSION
#define VER_PRODUCTVERSION_STR	VER_FILEVERSION_STR

#define VER_COMPANYNAME_STR	 	"Linbit"
#define VER_FILEDESCRIPTION_STR		"DRBD driver for Windows"
#define VER_INTERNALNAME_STR		"${VER_INTERNALNAME_STR}"
#define VER_LEGALCOPYRIGHT_STR		"GPL"
#define VER_LEGALTRADEMARKS1_STR	"DRBD"
#define VER_LEGALTRADEMARKS2_STR	"WinDRBD"
#define VER_ORIGINALFILENAME_STR	"WinDRBD"
#define VER_PRODUCTNAME_STR		VER_INTERNALNAME_STR

1 VERSIONINFO
FILEVERSION    	VER_FILEVERSION
PRODUCTVERSION 	VER_PRODUCTVERSION

// The constants need #include <windows.h> which we don't have here.
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
sed "s#^DriverVer.*#DriverVer = $(date +%m/%d/%Y),${WINDRBD_VERSION}  ;Replaced by build magic#" ./windrbd/windrbd.inf.in > ${OUTPATH}/windrbd.inf

## inno-setup version include file
echo \#define MyAppVersion \"${GITHASH}\" > inno-setup/version.iss
echo \#define MyResourceVersion \"${WINDRBD_VERSION}\" > inno-setup/resource-version.iss
