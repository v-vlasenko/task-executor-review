import requests
from pprint import pprint


class Client:
    def __init__(self, host):
        self.host = host
        self.token = None

    def signup(self, username, password, account_name):
        data = {
            "data": {
                "attributes": {
                    "username": username,
                    "password": password,
                    "account_name": account_name
                }
            }
        }
        response = requests.post(f"{self.host}/auth/signup", json=data)
        if response.status_code == 201:
            self.token = response.json()["data"]["attributes"]["token"]
            return self.token
        else:
            return response.json()

    def login(self, username, password):
        data = {
            "data": {
                "attributes": {
                    "username": username,
                    "password": password
                }
            }
        }
        response = requests.post(f"{self.host}/auth/login", json=data)
        if response.status_code == 201:
            self.token = response.json()["data"]["attributes"]["token"]
            return self.token
        else:
            return response.json()

    def invite_user(self, new_username):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        data = {"data": {"attributes": {"new_username": new_username}}}
        response = requests.post(f"{self.host}/user/invite", json=data, headers=headers)
        return response.json()

    def get_info(self):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        response = requests.get(f"{self.host}/user/get_info", headers=headers)
        return response.json()


""" 
Example Usage:
client = Client("http://localhost:5000/api")

# Signup a new user
signup_response = client.signup("new_user", "password123", "new_account")
pprint(signup_response)

# Login with the created user
token = client.login("new_user", "password123")
pprint(token)

# Invite a new user
invite_response = client.invite_user("another_user")
pprint(invite_response)

# Get user information
info_response = client.get_info()
pprint(info_response)
"""
