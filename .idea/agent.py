import socket
import threading
import time

LINUX_IP = input("Enter Linux public IP: ").strip()
LINUX_PORT = 4444

while True:
    try:
        print(f"[Windows] Trying to connect to {LINUX_IP}:{LINUX_PORT}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((LINUX_IP, LINUX_PORT))
        print("[+] Connected to Linux!")

        def receive():
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    print("\n[Linux] " + data.decode())
                except:
                    break

        threading.Thread(target=receive, daemon=True).start()

        while True:
            msg = input("Windows> ")
            sock.send(msg.encode())

    except Exception as e:
        print(f"Connection failed: {e}")
        print("Retrying in 5 seconds...")
        time.sleep(5)
