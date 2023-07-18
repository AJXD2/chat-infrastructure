import socket
import json
import requests
import threading


class SocketServer:
    def __init__(self, host="localhost", port=8765):
        self.host = host
        self.port = port
        self.connections = []
        self.api = "http://192.168.68.127:5000/"

    def broadcast(self, message, sever=False):
        pass

    def login(self, jwt, connection):
        url = f"{self.api}user"
        resp = requests.get(url, json={"jwt": jwt})
        res = resp.json()
        if res.get("message") == "failed":
            connection.send(
                json.dumps({"message": "Invalid JWT", "error": "invalid_jwt"}).encode()
            )
            connection.close()
        if res["disabled"]:
            connection.send(
                json.dumps(
                    {"message": "Account disabled.", "error": "acc_disabled"}
                ).encode()
            )
            connection.close()

        self.connections.append({"username": res["username"], "connection": connection})
        return True

    def handle_client(self, connection, address):
        while True:
            message = connection.recv(1024).decode()
            message = json.loads(message)
            print(address)

            action = message["action"]
            if action == "message":
                pass
            elif action == "login":
                self.login(message["jwt"], connection)
            elif action == "logout":
                pass
            else:
                pass

            response = f"Received message: {message}"
            connection.send(response.encode())

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)

        print(f"Server started on {self.host}:{self.port}")

        while True:
            connection, address = server_socket.accept()
            print(f"Client connected from {address[0]}:{address[1]}")

            client_thread = threading.Thread(
                target=self.handle_client,
                args=(connection, address),
                daemon=True,
                name=f"{address[0]}:{address[1]}",
            )
            client_thread.start()


if __name__ == "__main__":
    server = SocketServer()
    server.start_server()
