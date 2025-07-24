FILES= cpthread.cpp
CCFLAGS= -g -fpermissive 
LIBS=-L/usr/lib -lssl -lcrypt -pthread
DEFINES= -DLINUX=1 -DDEBUG=1
CC= g++

ssltool: ssltool.cpp
	${CC} ${CCFLAGS} ${LIBS} ${DEFINES} ${FILES} ssltool.cpp ${LIBS} -o ssltool && echo "holy shit it compiled...";

all: ssltool

run: all
	echo "starting ssltool.... (run it as sudo for port 443/HTTPS)";
	ssltool 0.0.0.0 443 127.0.0.1 80 -s;

cleanall:
	rm ssltool

clean: cleanall
