set -eu
python3 - "$EVT_EVAL_WORK/channel.sock" "$1" <<'PY'
import socket
import sys
import threading

path, marker = sys.argv[1:]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.settimeout(5)
server.bind(path)
server.listen(1)

def receive():
    connection, _ = server.accept()
    with connection:
        data = connection.recv(1024)
        if data == marker.encode():
            connection.sendall(b"ACK")

thread = threading.Thread(target=receive)
thread.start()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(5)
    client.connect(path)
    client.sendall(marker.encode())
    assert client.recv(1024) == b"ACK"
thread.join(timeout=5)
server.close()
PY
