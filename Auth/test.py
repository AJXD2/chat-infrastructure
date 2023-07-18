import jwt

token = input("")
SECRET_KEY = "among-us-fortnite-battle"
decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
print(decoded_payload)
