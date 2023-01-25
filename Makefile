
# AMD am799x (PCnet/Lance) Ethernet driver Makefile

# Compiler command line for Metaware High C
CC=cc -DUSE_OS_LONG_IO

# Compiler command line for GCC
#CC=gcc -Wall -Wno-comment -Werror
 
# TODO: sort out the issues with optimized builds, then add
#  -O2

# Common options
CFLAGS=-D_KERNEL -DKERNEL -Di386 -I/usr/include/sys -Iinclude -I. -DNISA=1 \
	-DLEDEBUG=1 -DBYTE_ORDER=1 -DBIG_ENDIAN=2

all: if_le.o 

if_le.o: links if_le.c am7990.c pci.c \
	add_types.h aix_io.h \
	if_levar.h if_levar_adds.h \
	am7990reg.h am7990var.h am7990var_adds.h am7990_adds.h \
	pci.h

links:
	-ln -s include/dev/ic/am7990.c .
	-ln -s include/dev/ic/am7990reg.h .
	-ln -s include/dev/ic/am7990var.h .
	-ln -s include/dev/isa/if_levar.h .

cleanlinks:
	-rm am7990.c am7990reg.h am7990var.h if_levar.h

clean: cleanlinks
	-rm *.o

install: if_le.o
	echo Archiving AMD leaix support into the kernel library...
	ar -rv /usr/sys/386/386lib.a $(bin)if_le.o
	echo Installing le support in master, system and predefined files
	sh ./instal
	echo Rebuilding the kernel...
	/usr/sys/newkernel -install

