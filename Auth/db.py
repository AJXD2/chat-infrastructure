import bcrypt
import sqlite3
from dataclasses import dataclass
import re
from sqlite3 import Connection

MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 64
roles = ["admin", "moderator", "user"]
SALT = bcrypt.gensalt()


@dataclass
class User:
    id: int
    username: str
    password: str
    email: str
    role: str
    # Add more attributes as needed


class Database:
    def __init__(self, db="db.db"):
        self.db_file = f"./instance/{db}"
        self.conn_pool = None

        self.create_tables()

    def create_tables(self):
        with self.get_connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username text, password text, email text, role text)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS punishments(id int, operator text)"
            )

    def get_connection(self) -> Connection:
        if self.conn_pool is None:
            self.conn_pool = sqlite3.connect(self.db_file, check_same_thread=False)
        return self.conn_pool

    def convert_raw_to_user(self, raw):
        if raw is None:
            return None
        return User(*raw)

    def validate_email(self, email):
        # Regex pattern for email validation
        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"

        # Match the pattern against the email address
        if re.match(pattern, email):
            return True
        else:
            return False

    def get_user_by_name(self, username, check=False):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchall()

        if len(user) <= 0:
            if check:
                return False
            return None
        if check:
            return True
        return user[0]

    def get_user_by_id(self, id, check=False):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id=?", (id,))
            user = cursor.fetchall()

        if len(user) <= 0:
            if check:
                return False
            return None
        if check:
            return True
        return user[0]

    def create_user(self, username: str, password: str, email: str):
        if self.get_user_by_name(username):
            return {"status": "failed", "message": "user already exists"}
        if len(password) > MAX_PASSWORD_LEN:
            return {"status": "failed", "message": "password too long"}
        elif len(password) < MIN_PASSWORD_LEN:
            return {"status": "failed", "message": "password too short"}
        role = "user"
        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), SALT).decode("utf-8")

        if not bcrypt.checkpw(password.encode("utf-8"), hashed_pw.encode("utf-8")):
            raise Exception("Oops! Password verification failed.")
        if email == "":
            email = "notset@example.com"
        if not self.validate_email(email):
            return {"status": "failed", "message": "invalid email"}

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                (username, hashed_pw, email, role),
            )
            return {"status": "success"}

    def get_all_users(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users")
            return cursor.fetchall()

    def disable_user(
        self, id: int = None, username: str = None, operator: str = "system"
    ):
        if username is not None:
            user = self.get_user_by_name(username)
            if user is not None:
                id = user.id
        if id is not None:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO punishments VALUES (?,?)", (id, operator))
                conn.commit()
            return {"status": "success"}

    def enable_user(
        self, id: int = None, username: str = None, operator: str = "system"
    ):
        if username is not None:
            id = self.get_user_by_name(username)[0]
        if id is not None:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM punishments WHERE id=?", (id,))
            return {"status": "success"}

    def is_disabled(self, id: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM punishments WHERE id=?", (str(id),))
            data = cursor.fetchall()

        conn.close()
        return True if len(data) > 0 else False

    def update_user(
        self, id, new_username=None, new_password=None, new_email=None, new_role=None
    ):
        print(f"`{new_password}`")
        old = self.convert_raw_to_user(self.get_user_by_id(id))
        if old == None:
            return {"status": "failed", "message": "user does not exist"}
        new_username = new_username if new_username not in (None, "") else old.username
        new_password = (
            bcrypt.hashpw(new_password.encode("utf-8"), SALT).decode("utf-8")
            if new_password not in (None, "")
            else old.password
        )
        new_email = new_email if new_email not in (None, "") else old.email
        new_role = new_role if new_role not in (None, "") else old.role

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET username=?, password=?, email=?, role=? WHERE id=?",
                (new_username, new_password, new_email, new_role, id),
            )
        return {"status": "success"}

    def validate_user_with_id(self, id: int, password: str):
        user = self.convert_raw_to_user(self.get_user_by_id(id))
        if user is None:
            return {"status": "failed", "message": "user not found"}

        password_hash = str(user.password)
        if type(password_hash) != bytes:
            password_hash = password_hash.encode("utf-8")

        if bcrypt.checkpw(password.encode("utf-8"), password_hash):
            return {"status": "success"}
        else:
            return {"status": "failed", "message": "wrong password"}

    def validate_user(self, username: str, password: str):
        user = self.convert_raw_to_user(self.get_user_by_name(username))
        if user is None:
            return {"status": "failed", "message": "user not found"}

        password_hash = str(user.password)
        if type(password_hash) != bytes:
            password_hash = password_hash.encode("utf-8")

        if bcrypt.checkpw(password.encode("utf-8"), password_hash):
            return {"status": "success"}
        else:
            return {"status": "failed", "message": "wrong password"}

    def delete_user(self, username: str):
        user = self.convert_raw_to_user(self.get_user_by_name(username))
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM users WHERE username=?",
                (username,),
            )
            return {"status": "success"}


if __name__ == "__main__":
    with Database() as db:
        username = input("Username> ")
        password = input("Password> ")
        email = input("Email> ")
        role = input("Role> ")

        resp = db.create_user(username, password, email, role)
        if resp["status"] == "failed":
            print(resp["message"])
        else:
            print("User created successfully.")
