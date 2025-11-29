import socket
import threading
import bcrypt

HOST, PORT = '127.0.0.1', 5555
BUFFER_SIZE = 1024

user_credentials: dict[str, str] = {}        # username -> hashed pw
connected_clients: dict[str, socket.socket] = {}  # username -> socket


# ------------ user management -----------------
def register_user(username: str, password: str) -> str:
    if username in user_credentials:
        return "Username already exists."
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_credentials[username] = hashed_pw
    return "User registered successfully."

def login_user(username: str, password: str) -> str:
    if username not in user_credentials:
        return "Username does not exist."
    if bcrypt.checkpw(password.encode(), user_credentials[username].encode()):
        return "Login successful."
    return "Incorrect password."


# ------------ messaging helpers ---------------
def broadcast(sender: str, msg: str, exclude: str | None = None) -> None:
    """Send a message to all connected users except *exclude*."""
    dead = []
    for user, sock in connected_clients.items():
        if user == exclude:
            continue
        try:
            sock.sendall(f"{sender}: {msg}".encode())
        except OSError:
            dead.append(user)          # remember broken sockets
    for user in dead:                  # clean them up later
        connected_clients.pop(user, None)

def send_private(sender: str, recipient: str, msg: str) -> str:
    sock = connected_clients.get(recipient)
    if not sock:
        return f"User {recipient} is not online."
    try:
        sock.sendall(f"PRIVATE from {sender}: {msg}".encode())
        return f"Message sent to {recipient}."
    except OSError:
        connected_clients.pop(recipient, None)
        return f"Could not deliver to {recipient}."


def notify_status(user: str, status: str) -> None:
    broadcast("Server", f"** {user} has {status} the chat **", exclude=None)


# ------------- per‑client thread --------------
def handle_client(sock: socket.socket, addr):
    username = None
    try:
        while True:
            raw = sock.recv(BUFFER_SIZE)
            if not raw:
                break                  # client closed connection
            cmd, *rest = raw.decode().split(" ", 1)
            data = rest[0] if rest else ""

            if cmd == "REGISTER":
                try:
                    u, p = data.split()
                    sock.sendall(register_user(u, p).encode())
                except ValueError:
                    sock.sendall(b"Usage: REGISTER username password")

            elif cmd == "LOGIN":
                try:
                    u, p = data.split()
                    reply = login_user(u, p)
                    sock.sendall(reply.encode())
                    if reply.startswith("Login successful"):
                        username = u
                        connected_clients[username] = sock
                        notify_status(username, "joined")
                    continue           # skip generic send at bottom
                except ValueError:
                    sock.sendall(b"Usage: LOGIN username password")

            elif cmd == "MESSAGE" and username:
                broadcast(username, data, exclude=None)
                sock.sendall(b"Message sent.")

            elif cmd == "PRIVATE" and username:
                try:
                    recip, pm = data.split(" ", 1)
                    sock.sendall(send_private(username, recip, pm).encode())
                except ValueError:
                    sock.sendall(b"Usage: PRIVATE recipient message")

            elif cmd == "LOGOUT" and username:
                sock.sendall(b"Goodbye!")
                break

            else:
                sock.sendall(b"Invalid command or not logged in.")
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        if username and username in connected_clients:
            connected_clients.pop(username, None)
            notify_status(username, "left")
        sock.close()


# ------------- main server loop ---------------
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            client, address = server.accept()
            print(f"New connection from {address}")
            threading.Thread(target=handle_client, args=(client, address), daemon=True).start()


if __name__ == "__main__":
    start_server()
