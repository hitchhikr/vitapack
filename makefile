CC = gcc

LIBS = -lzip -lz -lssp
FLAGS = -O3 -fstack-protector -L/mingw64/lib
CXXFLAGS = $(FLAGS)

EXEOBJS = src/vitapack.o

all: vitapack

clean: RemObj

RemObj:
	-rm -f $(EXEOBJS)

vitapack: $(EXEOBJS)
	$(CC) -o ./VitaPack $(FLAGS) $(EXEOBJS) $(LIBS)

src/vitapack.o: src/vitapack.c
	$(CC) -c -o $(@) $(FLAGS) $<
