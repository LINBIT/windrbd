

EWDK_PATH := ../

EWDK_INC := "$(EWDK_PATH)/ewdk/Program Files/Windows Kits/10/Include"

CONV_SRC := $(PWD)/drbd/drbd/
CONV_DEST := $(PWD)/converted-sources/
CONV_SCRIPTS := $(PWD)/conversion-scripts/

SOURCE_FILES := *.[ch]

export SHELL=bash


all: copy change msbuild

copy:
	mkdir -p $(CONV_DEST)/
	cd -a $(CONV_SRC) && make drbd_buildtag.c
	cp -a $(CONV_SRC)/$(SOURCE_FILES) $(CONV_DEST)/
	cp -a data/wdrbd9.vcxproj $(CONV_DEST)/

change:
	# These scripts must be callable multiple times
	set -e ; for cmd in $(CONV_SCRIPTS) ; do ( cd $(CONV_DEST) && $(CMD) ./$(SOURCE_FILES) ) ; done

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
