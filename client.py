import socket
import threading
import sys

HOST, PORT = '127.0.0.1', 5555
BUFFER_SIZE = 1024

def safe_send(sock: socket.socket, payload: str) -> str | None:
    """Send a command to the server and return its response."""
    try:
        sock.sendall(payload.encode())
        return sock.recv(BUFFER_SIZE).decode()
    except (ConnectionResetError, ConnectionAbortedError, OSError) as err:
        print(f"[ERROR] {err}")
        sock.close()
        sys.exit(1)

def listen_for_messages(sock: socket.socket) -> None:
    """Background listener thread for broadcast / private messages."""
    while True:
        try:
            msg = sock.recv(BUFFER_SIZE).decode()
            if not msg:        # server closed connection
                print("[INFO] Disconnected from server.")
                break
            print(msg)
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            print("[ERROR] Connection lost.")
            break

def chat_loop(sock: socket.socket, username: str) -> None:
    threading.Thread(target=listen_for_messages, args=(sock,), daemon=True).start()
    print(f"Welcome, {username}!  Type 'exit' to leave.")
    print("Use  @recipient message  for private messages.")

    while True:
        text = input("> ").strip()
        if text.lower() == "exit":
            safe_send(sock, "LOGOUT")
            break
        if text.startswith("@"):
            try:
                recipient, pm = text[1:].split(" ", 1)
                safe_send(sock, f"PRIVATE {recipient} {pm}")
            except ValueError:
                print("⚠️  Usage: @recipient message")
        else:
            safe_send(sock, f"MESSAGE {text}")

def main() -> None:
    print("Simple Chat Client\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        while True:
            choice = input("\n1) Register\n2) Login\n3) Exit\nSelect: ").strip()
            if choice == "1":                         # register
                u, p = input("Username: "), input("Password: ")
                print(safe_send(sock, f"REGISTER {u} {p}"))

            elif choice == "2":                       # login
                u, p = input("Username: "), input("Password: ")
                resp = safe_send(sock, f"LOGIN {u} {p}")
                print(resp)
                if "successful" in resp.lower():
                    chat_loop(sock, u)
                    break

            elif choice == "3":
                print("Goodbye!")
                break
            else:
                print("Invalid choice.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Client terminated.")
