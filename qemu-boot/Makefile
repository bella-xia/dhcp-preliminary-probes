CROSS=aarch64-linux-gnu-
CC=$(CROSS)gcc
LD=$(CROSS)ld
OBJCOPY=$(CROSS)objcopy 
CFLAGS=-O2 -ffreestanding -Wall -Wextra -nostdlib -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables
LDFLAGS=-T linker.ld -nostdlib

CSRC=main.c uart.c kstring.c
ASRC=start.S

COBJS=$(CSRC:.c=.o)
AOBJS=$(ASRC:.S=.o)
OBJS=$(COBJS) $(AOBJS)

all: bootloader.bin

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
 
%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@ -march=armv8-a 

bootloader.elf: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

bootloader.bin: bootloader.elf
	$(OBJCOPY) -O binary $< $@
 
clean:
	rm -f *.o *.elf *.bin
