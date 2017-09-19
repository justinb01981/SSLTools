FILES= cpthread.cpp
CCFLAGS= -g -fpermissive 
LIBS=-L/usr/lib -lssl -lcrypt -pthread
DEFINES= -DLINUX=1 -DDEBUG=1
CC= g++

ssltool: ssltool.cpp
	${CC} ${CCFLAGS} ${LIBS} ${DEFINES} ${FILES} ssltool.cpp ${LIBS} -o ssltool

all: ssltool

cleanall:
	rm ssltool

clean: cleanall
