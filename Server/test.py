import socket


def connect():
    host = "localhost"  # Replace with the server host
    port = 8765  # Replace with the server port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))

        while True:
            message = input("Enter a message (or 'exit' to quit): ")

            if message.lower() == "exit":
                break

            client_socket.sendall(message.encode())

            response = client_socket.recv(1024).decode()
            print(f"Received message: {response}")


if __name__ == "__main__":
    connect()
