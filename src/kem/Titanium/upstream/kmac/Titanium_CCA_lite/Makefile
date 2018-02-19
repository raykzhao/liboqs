CC=gcc
CFLAGS=-O3
OBJS=encrypt.o fastrandombytes.o kem.o ntt.o pack.o rng.o sampler.o
PROGRAM=libtitanium.a

all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	ar -r -c $(PROGRAM) $(OBJS)

clean:;
	rm -f *.o $(PROGRAM)

