CROSS=aarch64-linux-gnu-
CC=$(CROSS)gcc
LD=$(CROSS)ld
OBJCOPY=$(CROSS)objcopy 
CFLAGS = -O0 -g3 -ffreestanding -nostdlib \
         -Wall -Wextra -Werror=implicit-function-declaration \
         -fno-builtin -fno-stack-protector \
         -fno-unwind-tables -fno-asynchronous-unwind-tables \
         -mgeneral-regs-only
LDFLAGS=-T linker.ld -nostdlib

CSRC=main.c uart.c kstring.c cli_utils.c cli_gencmds.c cli_memcmds.c cli_dhcpcmds.c cli_virtiocmds.c dhcp_server.c virtio.c
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
