import logging


class Client:
    def __init__(self, host, http_client):
        self.host = host
        self.token = None
        self.logging = logging
        self.LOG = logging.getLogger(__name__)
        self._client = http_client

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

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
        response = self._client.post(f"{self.host}/api/auth/signup", json=data)
        if response.status_code == 201:
            self.LOG.info(f"New account {account_name} has been created by {username}.")
            self.token = response.json()["data"]["attributes"]["token"]
            return self.token

    def login(self, username, password):
        data = {
            "data": {
                "attributes": {
                    "username": username,
                    "password": password
                }
            }
        }
        response = self._client.post(f"{self.host}/api/auth/login", json=data)
        if response.status_code == 201:
            self.LOG.info(f"User {username} has been successfully logged in")
            self.token = response.json()["data"]["token"]
            return self.token

    def invite_user(self, new_username):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        data = {"data": {"attributes": {"new_username": new_username}}}
        response = self._client.post(f"{self.host}/api/user/invite", json=data, headers=headers)
        if response.status_code == 201:
            self.LOG.info(f"User {new_username} has been successfully invited")
            return response.json()

    def get_user_info(self, user_id):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        response = self._client.get(f"{self.host}/api/user/get_info/{user_id}", headers=headers)
        if response.status_code == 200:
            self.LOG.info(f"Info about user with id: {user_id} has been successfully retrieved")
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
