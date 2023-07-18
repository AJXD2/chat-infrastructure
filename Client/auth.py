import requests
import os
import time

CACHE_PATH = "./cache/jwt.cache"


class AuthenticationException(Exception):
    def __init__(self, message) -> None:
        self.message = message
        super().__init__(self.message)


class Authentication:
    def __init__(
        self, username: str = None, password: str = None, email: str = None
    ) -> None:
        self.username = username
        self.password = password
        self.email = email
        self.role = "none"
        self.id = -1
        self.api_url = "http://192.168.68.127:5000"
        self.jwt = ""
        self.logged_in = False
        self.online = False
        self.load_cache()
        self.get_status()

    def get_status(self):
        try:
            resp = requests.get(f"{self.api_url}/status")
            if resp.json()["status"] == "online":
                self.online = True
            else:
                self.online = False
        except requests.exceptions.ConnectionError:
            self.online = False

    def set_username(self, username: str):
        self.username = username

    def set_password(self, password: str):
        self.password = password

    def set_email(self, email: str):
        if email == "":
            email = "notset@example.com"
        self.email = email

    def get_data(self):
        if not self.logged_in:
            return None
        url = f"{self.api_url}/user"
        resp = requests.get(url, json={"jwt": self.jwt}).json()

        self.username = resp["username"]
        self.email = resp["email"]
        self.role = resp["role"]
        self.id = resp["id"]
        return True

    def punish(self, id: int, enable: bool = False):
        url = f"{self.api_url}/punishments"
        resp = requests.post(url, json={"id": id, "enable": enable, "jwt": self.jwt})
        return resp.json()["message"]

    def is_disabled(self, id: int = None):
        if id == None:
            id = self.id
        url = f"{self.api_url}/punishments"
        resp = requests.get(url, json={"id": id})
        return resp.json()

    def login(self):
        url = f"{self.api_url}/login"
        resp = requests.post(
            url, json={"username": self.username, "password": self.password}
        )
        if resp.status_code == 200:
            self.jwt = resp.json()["jwt"]
            self.logged_in = True
            self.cache()
        else:
            raise AuthenticationException(resp.json()["message"])

    def register(self):
        url = f"{self.api_url}/register"
        resp = requests.post(
            url,
            json={
                "username": self.username,
                "password": self.password,
                "email": self.email,
            },
        )

        if resp.status_code == 200:
            self.jwt = resp.json()["jwt"]
            self.cache()
        else:
            raise AuthenticationException(resp.json()["message"])

    def delete(self):
        url = f"{self.api_url}/delete"
        resp = requests.delete(url, json={"jwt": self.jwt})

        self.jwt = ""
        self.username = ""
        self.password = ""
        self.cache()

    def cache(self):
        cache_dir = os.path.dirname(CACHE_PATH)
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)

        with open(CACHE_PATH, "w") as f:
            f.write(self.jwt)

    def load_cache(self):
        if os.path.exists(CACHE_PATH):
            with open(CACHE_PATH, "r") as f:
                jwt = f.read()
                if jwt == "":
                    self.logged_in = False
                    return
                self.jwt = jwt
                self.logged_in = True
                self.get_data()
            return
        else:
            self.cache()

    def update(self, username=None, password=None, email=None):
        url = f"{self.api_url}/update"
        if username is not None:
            self.username = username
        if password is not None:
            self.password = password
        resp = requests.post(
            url,
            json={
                "username": username,
                "password": password,
                "email": email,
                "jwt": self.jwt,
            },
        )
        self.cache()
