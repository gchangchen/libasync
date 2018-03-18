

OBJ = async.o

DEBUG ?= 1
ifeq ($(DEBUG), 0)
	LDFLAGS +=-lm -s
	CFLAGS += -O2 -DNDEBUG
else
	LDFLAGS +=-lm
	CFLAGS += -g
endif

HAVE_LIBEV ?= 1
ifneq ($(HAVE_LIBEV), 0)
	CFLAGS += -DHAVE_LIBEV
	LDFLAGS +=-lev
endif


CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
AS = $(CROSS_COMPILE)as
CPP = $(CC) -E
AR = $(CROSS_COMPILE)ar
NM = $(CROSS_COMPILE)nm
STRIP = $(CROSS_COMPILE)strip
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump

INCLUDE_PATH = include
CFLAGS += -I$(INCLUDE_PATH) -std=gnu99


export CC LD AS CPP AR NM STRIP OBJCOPY OBJDUMP CFLAGS LDFLAGS

demo:demo.o $(OBJ)
	$(CC) $^ -o $@ $(LDFLAGS) 

.PHONY:clean
clean:
	rm -rf *.o demo



