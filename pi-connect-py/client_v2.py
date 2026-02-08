import serial
import sys
import time
import threading

SERIAL_PORT = '/dev/ttyUSB0'  # change if needed
BAUD_RATE = 115200

def main():
    print(f"[Client] Connecting to {SERIAL_PORT}...")
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1)
        print("[Client] Serial port opened")
    except Exception as e:
        print(f"[Client] Error: {e}")
        sys.exit(1)

    # -------------------------------
    # Handshake: Wait for BOOT -> send ACK
    # -------------------------------
    print("[Client] Waiting for bootloader signal...")
    while True:
        if ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if line:
                print(f"[Client] Received: {line}")
                if "BOOT" in line:
                    print("[Client] Bootloader detected! Sending ACK...")
                    ser.write(b"ACK")
                    ser.flush()
                    time.sleep(0.01)  # small delay to let Pi process
                    break

    print("[Client] Handshake complete. Entering interactive mode.\n")
    print("=" * 50)

    # -------------------------------
    # Thread: continuously read Pi output
    # -------------------------------
    def read_pi():
        while True:
            try:
                if ser.in_waiting > 0:
                    data = ser.read(ser.in_waiting)
                    sys.stdout.write(data.decode('utf-8', errors='ignore'))
                    sys.stdout.flush()
                time.sleep(0.01)
            except serial.SerialException:
                break

    threading.Thread(target=read_pi, daemon=True).start()

    # -------------------------------
    # Interactive input: send char-by-char
    # -------------------------------
    try:
        while True:
            cmd = input()  # user types command
            for c in cmd:
                ser.write(c.encode())
                ser.flush()
                time.sleep(0.005)  # small delay per char
            ser.write(b'\n')  # terminate command
            ser.flush()
    except KeyboardInterrupt:
        print("\n[Client] Exiting...")
        ser.close()

if __name__ == "__main__":
    main()
