import json
import socket
from rich.panel import Panel
from rich import print
from auth import Authentication as Auth
from auth import AuthenticationException as AuthErr
from rich.console import Console
from rich.prompt import Prompt
from rich.status import Status
import requests


class Client:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.auth = Auth()
        self.con = Console()
        self.preset_menus = {
            "main": [
                ("Join", self.join),
                ("Login", self.login),
                ("Register", self.register),
                ("Settings", self.account),
                ("Exit", exit),
            ],
        }

    def join(self):
        ans = Prompt.ask(
            "Method of joining [violet][IP / Friend (WIP)][/]",
            console=self.con,
            choices=["ip", "IP", "Friend (WIP)", "friend"],
            show_choices=False,
        )

        if ans.lower() == "ip":
            while True:
                ip = Prompt.ask("IP")
                port = Prompt.ask("Port (press enter for default)")
                if port == "":
                    port = 5050
                try:
                    port = int(port)
                except ValueError:
                    print("Port must be number.")

    def __join_by_ip__(self, ip: str, port: int):
        self.socket.connect((ip, port))

    def account(self):
        self.con.clear()
        a = self.auth.logged_in
        res = self.auth.get_data()
        if res == None:
            self.show_menu(
                "Main Menu",
                subtitle=f"[red bold]Login First[/]",
                options=self.preset_menus["main"],
            )
        print("Details")
        print("Username:", self.auth.username)
        print("Password:", "*" * len(self.auth.username))
        print(
            "Email:",
            "NotSet" if self.auth.email == "notset@example.com" else self.auth.email,
        )
        print(f"Role: {self.auth.role}")

        ans = Prompt.ask(
            "Chose an action",
            choices=["Edit", "Back", "Admin"]
            if self.auth.role == "admin"
            else ["Edit", "Back"],
        )

        if ans.lower() == "admin":
            self.con.clear()
            self.show_menu(
                "Main Menu",
                "[red bold]Admin panel is in maintenance![/]",
                options=self.preset_menus["main"],
            )
            while True:
                print(
                    "[green]Welcome to the admin panel. Please input the id of the user you want to lookup!. Enter 'back' or press 'ctrl + c' to exit the panel."
                )
                try:
                    id = Prompt.ask("Enter ID", console=self.con)

                    if id.lower() == "back":
                        self.show_menu(
                            "Main Menu",
                            "[red bold]Exited admin panel[/]",
                            options=self.preset_menus["main"],
                        )
                    id = int(id)
                    resp = self.auth.punish(id, enable=False)
                    if resp != "success":
                        self.show_menu(
                            "Main Menu",
                            subtitle=f"[red bold]Operation failed (PUNISH USER WITH id={id})[/]",
                            options=self.preset_menus["main"],
                        )

                    break
                except KeyboardInterrupt:
                    self.show_menu(
                        "Main Menu",
                        "[red bold]Exited admin panel[/]",
                        options=self.preset_menus["main"],
                    )
                except ValueError:
                    self.con.clear()
                    print("[red bold]ID must be integer![/]")
        elif ans.lower() == "edit":
            print("Leave the fields that you dont want to change blank.")
            username = Prompt.ask("Username", console=self.con)
            password = Prompt.ask(
                "Password (Hidden for security)",
                password=True,
                console=self.con,
            )
            email = Prompt.ask("Email:")

            self.auth.update(username, password, email)
            self.show_menu(
                "Main Menu",
                "[green bold]Updated Account![/]",
                self.preset_menus["main"],
            )
        self.show_menu("Main Menu", options=self.preset_menus["main"])

    def login(self):
        self.con.clear()
        if not self.auth.online:
            print(
                "[red bold]Auth servers are down. Please contact @ajxd2 on discord. Keep in mind the auth servers restart at 12:00 AM EST every day."
            )
            exit()
        while True:
            username = Prompt.ask("Enter your username", console=self.con)
            password = Prompt.ask(
                "Enter your password (Hidden for security)",
                password=True,
                console=self.con,
            )

            self.auth.set_username(username)
            self.auth.set_password(password)

            try:
                self.auth.login()
                break
            except requests.exceptions.ConnectionError:
                print(
                    "[red]Authentication server are down right now. Please login later or contact @ajxd2 on discord[/]"
                )
                exit(1)
            except AuthErr as e:
                print(e)
                if e.message == "wrong password":
                    self.con.clear()
                    print("[red]Wrong password!")
                    continue
                elif e.message == "user not found":
                    self.con.clear()
                    print("[red]Invalid user!")
                    continue
            except KeyboardInterrupt:
                exit()
        self.show_menu(
            title="Main Menu",
            subtitle="[green bold]Logged in!",
            options=self.preset_menus["main"],
        )

    def register(self):
        if not self.auth.online:
            print(
                "[red bold]Auth servers are down. Please contact @ajxd2 on discord. Keep in mind the auth servers restart at 12:00 AM EST every day."
            )
            exit()
        while True:
            try:
                username = Prompt.ask("Enter your username", console=self.con)
                email = Prompt.ask("Email (leave blank for none)")
                password = Prompt.ask(
                    "Enter your password (Hidden for security)",
                    password=True,
                    console=self.con,
                )
                verify_password = Prompt.ask(
                    "Verify password (Hidden for security)",
                    password=True,
                    console=self.con,
                )
            except KeyboardInterrupt:
                self.show_menu(
                    "Main Menu",
                    "[red]Canceled registration[/]",
                    options=self.preset_menus["main"],
                )
            if password != verify_password:
                print("[red bold]Passwords dont match!")
                continue
            if len(password) < 8:
                print("[red bold]Password must be at least 8 characters!")
                continue
            break
        self.auth.set_username(username)
        self.auth.set_password(password)
        self.auth.set_email(email)
        with Status("Registering in with auth servers...") as status:
            try:
                self.auth.register()

            except requests.exceptions.ConnectionError:
                print(
                    "[red]Authentication server are down right now. Please register later or contact @ajxd2 on discord[/]"
                )
                exit(1)

        self.show_menu(
            title="Main Menu",
            subtitle="[green bold]Registered and Logged in![/]",
            options=self.preset_menus["main"],
        )

    def show_menu(
        self,
        title: str = "",
        subtitle: str = "",
        options: list[tuple[str, callable]] = None,
    ):
        while True:
            self.con.clear()
            if title != "":
                print(title)
            if subtitle != "":
                print(subtitle)
            subtitle = ""
            for i, item in enumerate(options):
                print(i + 1, item[0])
            try:
                ans = int(input("Select a option by the number\n>")) - 1
                if ans > len(options) - 1:
                    subtitle = "[red bold]Invalid option[/]"
                    continue
                break
            except ValueError:
                subtitle = "[red bold]Must be number.[/]"
                continue
            except KeyboardInterrupt:
                exit()

        if callable(options[ans][1]):
            options[ans][1]()


def foo():
    print("foo")


def bar():
    print("bar")


bar = ""

cl = Client()
try:
    cl.show_menu(options=cl.preset_menus["main"])
except KeyboardInterrupt:
    exit()
