import serial
import sys
import time

SERIAL_PORT = '/dev/ttyUSB0'
BAUD_RATE = 115200

def main():
    print(f"[Client] Connecting to {SERIAL_PORT}...")
    
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
        print("[Client] Serial port opened")
    except Exception as e:
        print(f"[Client] Error: {e}")
        sys.exit(1)
    
    # Wait for BOOT signal
    print("[Client] Waiting for bootloader signal...")
    boot_received = False
    
    while not boot_received:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if line:
                print(f"[Client] Received: {line}")
                
                if "BOOT" in line:
                    print("[Client] Bootloader detected! Sending ACK...")
                    ser.write(b"ACK")
                    ser.flush()
                    time.sleep(0.01)
                    boot_received = True
                    break

    # Now just echo everything
    print("[Client] Handshake complete. Entering interactive mode.\n")
    print("=" * 50)
    
    def send_command(cmd: str):
        for c in cmd:
            ser.write(c.encode())
            ser.flush()
            time.sleep(0.005)  # small delay helps Pi keep up
        ser.write(b'\n')  # terminate command
        ser.flush()

    send_command("") # clean buffer
    
    CMDS = ["help", "info", 
            "usage", 
            "hexdump 0x8000 64",
            "dump32 0x8000 16",
            "dhcp_init", 
            "dhcp_test", "dhcp_test", "dhcp_leased", "dhcp_test",
            "usage"]

    for cmd in CMDS:
        send_command(cmd)
        time.sleep(0.2) # give it some time to respond
    
    try:
        while True:
            # Read from serial
            if ser.in_waiting > 0:
                data = ser.read(ser.in_waiting)
                sys.stdout.write(data.decode('utf-8', errors='ignore'))
                sys.stdout.flush()
            
            # TODO: Add keyboard input handling here if needed
            time.sleep(0.01)
            
    except KeyboardInterrupt:
        print("\n[Client] Exiting...")
        ser.close()

if __name__ == "__main__":
    main()
