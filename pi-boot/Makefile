CROSS=arm-none-eabi-
CC=$(CROSS)gcc
LD=$(CROSS)ld
OBJCOPY=$(CROSS)objcopy 
ARCH_FLAGS = -march=armv6zk -mtune=arm1176jzf-s -mfpu=vfp -mfloat-abi=hard
CFLAGS = -O0 -g3 -ffreestanding -nostdlib \
         -Wall -Wextra -Werror=implicit-function-declaration \
         -fno-builtin -fno-stack-protector \
         -fno-unwind-tables -fno-asynchronous-unwind-tables \
         $(ARCH_FLAGS)

LDFLAGS=-T linker.ld -nostdlib

CSRC=main.c gpio.c uart.c uart_aux.c kstring.c cli_utils.c cli_gencmds.c cli_memcmds.c dhcp_server.c
ASRC=start.S mmio.S

COBJS=$(CSRC:.c=.o)
AOBJS=$(ASRC:.S=.o)
OBJS=$(COBJS) $(AOBJS)

all: kernel.img

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
 
%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@ -march=armv8-a 

kernel.elf: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

kernel.img: kernel.elf
	$(OBJCOPY) -O binary $< $@
 
clean:
	rm -f *.o *.elf *.bin
