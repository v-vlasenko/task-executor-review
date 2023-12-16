import secrets
import string
from datetime import datetime
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, jwt


class Account(db.Model):
    id = db.Column(db.Integer, autoincrement=True, unique=True)
    account_name = db.Column(db.String(100), unique=True, nullable=False)
    account_id = db.Column(db.String(64), primary_key=True, default=lambda: str(uuid4()), index=True)


class Users(db.Model):
    id = db.Column(db.Integer, autoincrement=True, unique=True)
    user_id = db.Column(db.String(64), primary_key=True, default=lambda: str(uuid4()), index=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    account_id = db.Column(db.String(36), db.ForeignKey('account.account_id'), nullable=False)
    account = db.relationship('Account', backref='users')
    is_owner = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def generate_temp_password(length=16):
        characters = string.ascii_letters + string.digits + string.punctuation
        temp_password = ''.join(secrets.choice(characters) for _ in range(length))
        return temp_password


class TokenBlockList(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    jti = db.Column(db.String(), nullable=True)
    revoked_at = db.Column(db.DateTime(), default=datetime.utcnow)


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return Users.query.filter_by(username=identity).first()
