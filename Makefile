

EWDK_PATH := ../

EWDK_INC := "$(EWDK_PATH)/ewdk/Program Files/Windows Kits/10/Include"

CONV_SRC := $(PWD)/drbd/
CONV_DEST := $(PWD)/converted-sources/
CONV_SCRIPTS := $(PWD)/conversion-scripts/

SOURCE_FILES := *.[ch]

export SHELL=bash


all: copy change msbuild

copy:
	mkdir -p $(CONV_DEST)/
	cp -ra $(CONV_SRC)/* $(CONV_DEST)
	cd $(CONV_SRC)/drbd && echo 'const char *drbd_buildtag(void){return "WDRBD";}' > drbd_buildtag.c
	cp -a ./Makefile.win $(CONV_DEST)/Makefile
	cp -a ./ms-cl.cmd $(CONV_DEST)/
	cp -a data/wdrbd9.vcxproj $(CONV_DEST)/drbd

change:
	# These scripts must be callable multiple times
	set -e ; for cmd in $(CONV_SCRIPTS)/*.sh ; do ( cd $(CONV_DEST)/drbd && $$cmd ./$(SOURCE_FILES) ) ; done

msbuild:
	if type msbuild.exe                                     \
	then                                                    \
		cd "$(CONV_DEST)"                                   \
		msbuild.exe                                         \
	else                                                    \
		@echo "Please call MSBUILD.EXE from within the"     \
		@echo "  $(CONV_DEST)"                              \
		@echo "directory."                                  \
		exit 1                                              \
	fi

clean:
	test -n "$(CONV_DEST)" && test -n "$(SOURCE_FILES)" && rm -f "$(CONV_DEST)/$(SOURCE_FILES)" # Be careful

# vim: set ts=8 sw=8 noet : 
