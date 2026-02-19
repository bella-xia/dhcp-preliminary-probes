# Setup Environment on Windows
Build Docker: run `docker_build.sh` in WSL or directly run `docker build -t qemu-baremetal .` in PowerShell. \
Start Docker: run `docker_run.sh` in WSL or directly run the command in `docker_run.sh` in PowerShell.

# QEMU Usage
Run `make` then `init_virt.sh`

# Monitor Network Traffic
After starting QEMU, check `ip link` in Docker (or your host if Docker isn't used). \
There should be a device called "tap0". This device will disappear once you shut down QEMU. \
In Docker (or your host), run `[sudo] ip link set tap0 up`, then `[sudo] tcpdump -i tap0`. \
In QEMU, use `virtio_test` to check its network RX/TX works.

# CLI Functionalities

## general functions
1. `help` gives overview of existing functionalities
```
u-boot> help
Available commands:
  help - Show this help
  echo <input> - Echo back <input>
  exit - Exit terminal
  clear - Clear terminal history
  info - Provides info on memory alignment
  usage - Provides snapshot on current RAM and stack usage
  peek <addr> - Display 32-bit word at specified <addr>
  hexdump <addr> <len> - Dump <len> bytes of memory starting <addr>
  dump32 <addr> <count> - Dump <count> 32-bit words starting <addr>
```

2. `echo` echoes back with user input
```
u-boot> echo hello world!
hello world!
u-boot> echo jkfjdskfjksfjkdjfkd ff;mdsfcsmcoscs
jkfjdskfjksfjkdjfkd ff;mdsfcsmcoscs
```

3. `clear` cleans content displayed on the current terminal
   
4. `exit` currently exits the main program and continuously hanging in emulator (to emulate hardware-level behavior)
```
u-boot> exit
exiting... (still requires Ctrl-a + x to exit qemu)
QEMU: Terminated
$
```

## memory-related functions
1. `info` provides bootloader memory mapping information
```
u-boot> info
==== Bootloader Info ====
 .text   : 0x40080000 - 0x4008112c (0x112c bytes)
 .rodata : 0x40081130 - 0x400815cd (0x49d bytes)
 .data   : 0x400815d0 - 0x400816a8 (0xd8 bytes)
 .bss    : 0x40081710 - 0x40081710 (0x0 bytes)
 stack   : 0x40081710 - 0x40091710 (0x10000 bytes)
```

2. `usage` gives a snapshot on current memory and stack usage
```
u-boot> usage
==== Usage Stats ====
 stack allocated: 0x10000 bytes (100%)
 stack used: 0x130 bytes (0%)
 stack free: 0xfed0 bytes (99%)

 total memory size: 0x800000 bytes (100%)
 static segment mapped: 0x1710 bytes (0%)
 dynamic stack allocated: 0x10000 bytes (0%)
 total memory reserved: 0x11710 bytes (0%)
 total memory free: 0x7ee8f0 bytes (99%)
```
3.  `peek` gives the 32-bit hex value at a designated address. Used for debugging
```
u-boot> peek 0x40080000
0x0000000040080000: 0x58000180
u-boot> peek 0x40080004
0x0000000040080004: 0x9100001f
u-boot> peek 0x40080008
0x0000000040080008: 0x58000180
```
*(for example, by looking at the first some 32-bit hexes starting in .text section, we should be able to translate them into ARM assembly instructions that is loaded into the system (believe the instruction at 0x40080000 is ldr)*

4. `hexdump` gives a formatted overview into a range of memory represented in 64-bit hex values. Used for debugging, especially for string values such as .data or .rodata
```
u-boot> hexdump 0x40081130 64
0x0000000040081130: 48 65 6c 6c 6f 2c 20 6d  69 6e 69 6d 61 6c 20 62 | Hello, minimal b
0x0000000040081140: 6f 6f 74 6c 6f 61 64 65  72 21 0a 00 00 00 00 00 | ootloader!......
0x0000000040081150: 53 69 6d 70 6c 65 20 43  4c 49 20 2d 20 74 79 70 | Simple CLI - typ
0x0000000040081160: 65 20 27 68 65 6c 70 27  20 66 6f 72 20 63 6f 6d | e 'help' for com
u-boot> hexdump 0x40081400 64
0x0000000040081400: 49 6e 76 61 6c 69 64 20  6c 65 6e 67 74 68 20 28 | Invalid length (
0x0000000040081410: 6d 61 78 20 34 30 39 36  29 0a 00 00 00 00 00 00 | max 4096).......
0x0000000040081420: 3a 20 00 00 00 00 00 00  20 20 20 00 00 00 00 00 | : ......   .....
0x0000000040081430: 7c 20 00 00 00 00 00 00  49 6e 76 61 6c 69 64 20 | | ......Invalid 
```
*(the two examples above are chosen from the range of .rodata addresses specified by info)*

5. `dump32` gives a formatted overview into a range of memory represented in 32-bit hex values. Used for debugging, especially for hex-formatted ARM assembly instructions
```
u-boot> dump32 0x40080000 16
0x0000000040080000: 0x58000180 0x9100001f 0x58000180 0x580001a1 
0x0000000040080010: 0xeb01001f 0x5400006a 0xf800841f 0x17fffffd 
0x0000000040080020: 0x94000010 0xd503205f 0x17ffffff 0x00000000 
0x0000000040080030: 0x40091710 0x00000000 0x40081710 0x00000000 
```

## run parser_test
`parser_test` is a loop that receives Ethernet packets through virtio, parses DHCP packets, generates DHCP responses, and sends response packets back through virtio.
1. run ./init_virt.sh in one terminal, use `parser_test` command to start the loop, use `q` to quit the loop
2. in another terminal, go inside docker then set up dhcp client:
    install DHCP client (first time only):
    ```
    apt-get update
    apt-get install -y isc-dhcp-client
    ```
    run dhcp client 
    ```
    dhclient -d -v tap0  
    ```
    to clear all cached state and perform a fresh DHCP handshake:
    ```
    dhclient -r tap0 && ip addr flush dev tap0 && rm -f /var/lib/dhcp/dhclient.leases && ip link set tap0 down && ip link set tap0 up && dhclient -d -v tap0
    ```
