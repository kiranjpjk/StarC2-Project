import socket

# Listen on all network interfaces
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))

print(f"[Windows] Listening on UDP port {SERVER_PORT}...")

last_client = None

while True:
    data, addr = sock.recvfrom(1024)
    message = data.decode()
    print(f"\nReceived from {addr}: {message}")

    # Store the address of the last sender
    last_client = addr

    # Let Windows user send a reply
    reply = input("Enter reply (or leave empty to skip): ").strip()
    if reply and last_client:
        sock.sendto(reply.encode(), last_client)
        print(f"Replied to {last_client}")
