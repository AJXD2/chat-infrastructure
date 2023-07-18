from flask import Flask
from flask_restful import Api, reqparse
import jwt
from db import Database
from dataclasses import asdict
import json

global DEBUG
DEBUG = True
app = Flask(__name__)
api = Api(app)
SECRET_KEY = "among-us-fortnite-battle"
from flask_restful import Resource


class UserUpdate(Resource):
    def post(self):
        # Create a request parser
        db = Database()
        parser = reqparse.RequestParser()

        # Define the expected arguments
        parser.add_argument("jwt", type=str, required=True)
        parser.add_argument("username", type=str, required=False)
        parser.add_argument("password", type=str, required=False)
        parser.add_argument("email", type=str, required=False)
        parser.add_argument("role", type=str, required=False)

        # Parse the request arguments
        args = parser.parse_args()

        # Retrieve the username and password from the parsed arguments
        wt = jwt.decode(args.get("jwt"), SECRET_KEY, "HS256")
        username = args.get("username")
        password = args.get("password")
        email = args.get("email")
        role = args.get("role")

        # Perform your authentication logic here

        resp = db.update_user(
            wt["id"],
            new_username=username,
            new_password=password,
            new_email=email,
            new_role=role,
        )

        if resp["status"] == "failed":
            return {"message": resp["message"]}, 401
        user = db.convert_raw_to_user(db.get_user_by_id(wt["id"]))

        payload = asdict(user)
        payload.pop("password")
        return {
            "message": "update Success",
            "jwt": jwt.encode(payload, SECRET_KEY, algorithm="HS256"),
        }


class PunishmentHandle(Resource):
    def post(self):
        # Create a request parser
        parser = reqparse.RequestParser()

        # Define the expected arguments
        parser.add_argument("id", type=str, required=True)
        parser.add_argument("jwt", type=str, required=True)
        parser.add_argument("enable", type=bool, required=False)

        # Parse the request arguments
        args = parser.parse_args()

        # Set the 'enable' argument to False if it's not provided
        if args.get("enable", None) is None:
            args["enable"] = False

        # Decode the JSON Web Token
        wt = jwt.decode(args["jwt"], SECRET_KEY, "HS256")

        # Validate the user with the provided ID and password
        db = Database()
        resp = db.validate_user_with_id(wt["id"], wt["password"])

        # If the user validation fails, return an error message with status code 403 (Forbidden)
        if resp["status"] == "failed":
            return {"message": resp["message"]}, 403

        # If the user is not an admin, return an error message with status code 401 (Unauthorized)
        if wt["role"] != "admin":
            return {"message": "invalid permissions"}, 401

        # Enable or disable the user based on the 'enable' argument
        if args["enable"] == False:
            db.disable_user(args["id"], operator=wt["username"])
        elif args["enable"]:
            db.enable_user(args["id"])

        # Return a success message
        return {"message": "success"}

    def get(self):
        db = Database()
        parser = reqparse.RequestParser()

        # Define the expected arguments
        parser.add_argument("id", type=str, required=True)
        args = parser.parse_args()
        return db.is_disabled(args["id"])


class UserRegistration(Resource):
    def post(self):
        # Create a request parser
        db = Database()
        parser = reqparse.RequestParser()

        # Define the expected arguments
        parser.add_argument("username", type=str, required=True)
        parser.add_argument("password", type=str, required=True)
        parser.add_argument("email", type=str, required=True)
        parser.add_argument("role", type=str, required=False)

        # Parse the request arguments
        args = parser.parse_args()

        # Retrieve the username and password from the parsed arguments
        username = args["username"]
        password = args["password"]
        email = args["email"]
        role = args.get("role")

        # Perform your authentication logic here
        resp = db.create_user(username, password, email)
        if resp["status"] == "failed":
            return {"message": resp["message"]}, 401

        user = db.convert_raw_to_user(db.get_user_by_name(username))
        payload = asdict(user)
        payload["password"] = password

        return {
            "message": "registration successful",
            "jwt": jwt.encode(payload, SECRET_KEY, algorithm="HS256"),
        }


class LoginResource(Resource):
    def post(self):
        # Create a request parser
        db = Database()
        parser = reqparse.RequestParser()

        # Define the expected arguments
        parser.add_argument("username", type=str, required=True)
        parser.add_argument("password", type=str, required=True)

        # Parse the request arguments
        args = parser.parse_args()

        # Retrieve the username and password from the parsed arguments
        username = args["username"]
        password = args["password"]

        # Perform your authentication logic here
        resp = db.validate_user(username, password)
        if resp["status"] == "failed":
            print(
                password,
            )
            return {"message": resp["message"]}, 401
        user = db.convert_raw_to_user(db.get_user_by_name(username))
        payload = asdict(user)
        payload["password"] = password

        return {
            "message": "login successful",
            "jwt": jwt.encode(payload, SECRET_KEY, algorithm="HS256"),
        }


class UserDataResource(Resource):
    def get(self):
        db = Database()
        parser = reqparse.RequestParser()

        # Define the expected arguments
        parser.add_argument("jwt", type=str, required=True)
        jswt = parser.parse_args()["jwt"]
        try:
            user = jwt.decode(jswt, SECRET_KEY, "HS256")
        except jwt.exceptions.DecodeError:
            return {"message": "failed"}
        user.pop("password")
        user["disabled"] = db.is_disabled(user["id"])
        return user


class DeleteResource(Resource):
    def delete(self):
        db = Database()
        parser = reqparse.RequestParser()

        # Define the expected arguments
        parser.add_argument("jwt", type=str, required=True)

        jswt = parser.parse_args()["jwt"]
        user = jwt.decode(jswt, SECRET_KEY, "HS256")
        db.get_user_by_id(user["id"])
        resp = db.validate_user(user["username"], user["password"])
        if resp["status"] == "failed":
            return {"message": resp["message"]}, 401

        db.delete_user(user["username"])

        return {"message": "deleted user"}


# Add more resource classes for additional endpoints

api.add_resource(UserRegistration, "/register")
api.add_resource(LoginResource, "/login")
api.add_resource(DeleteResource, "/delete")
api.add_resource(UserUpdate, "/update")
api.add_resource(PunishmentHandle, "/punishments")
api.add_resource(UserDataResource, "/user")


@app.route("/status")
def status():
    return {"status": "online"}


# Add more resources as needed
if __name__ == "__main__":
    app.run(host="0.0.0.0")
    if DEBUG:
        import os
