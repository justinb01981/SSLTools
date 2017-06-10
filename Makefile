FILES= cpthread.cpp
CCFLAGS= -g -fpermissive 
LIBS=-lpthread -lcrypto -lssl -pthread
DEFINES= -DLINUX=1 -DDEBUG=1
OUTPUT= sslclient
CC= g++

ssltool: ssltool.cpp
	${CC} ${CCFLAGS} ${LIBS} ${DEFINES} ${FILES} ssltool.cpp -o ssltool

all: ssltool

cleanall:
	rm ssltool

clean: cleanall
