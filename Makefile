# the compiler: gcc for C program, define as g++ for C++
CC = g++

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -lpcap -fpermissive

# the build target executable:
TARGET1 = dnsinject
TARGET2 = dnsdetect

all: $(TARGET1).cpp $(TARGET2).cpp
	$(CC) $(CFLAGS) -o $(TARGET1) $(TARGET1).cpp
	$(CC) $(CFLAGS) -o $(TARGET2) $(TARGET2).cpp

clean:
	$(RM) $(TARGET1) $(TARGET2)
