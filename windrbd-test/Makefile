OBJS=main.o drbd-device.o
PROG=windrbd-test.exe
CPPFLAGS=-Wall
# DRIVE ?= H:
DRIVE ?= F:
# SIZE ?= 52387328
SIZE ?= 52428800
# SIZE ?= 52387840
# FORCE ?= ""
FORCE ?= --force

all: $(PROG)

$(PROG): $(OBJS)
	g++ $(OBJS) -o $(PROG) -L/usr/local/lib -lgtest

test: all
	./windrbd-test.exe --drive $(DRIVE) --expected-size $(SIZE) $(FORCE)

install: all
	cp $(PROG) /usr/local/bin

clean:
	rm -f $(PROG) $(OBJS)

main.o: main.cpp drbd-device.hpp
drbd-device.o: drbd-device.cpp drbd-device.hpp
