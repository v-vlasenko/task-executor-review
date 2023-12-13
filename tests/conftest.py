import pytest
from app import create_app, db
from app.models import Users, Account
from config import Config
from uuid import uuid4


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'


@pytest.fixture
def app():
    app = create_app(config_class=TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def create_user_owner(app, create_account):
    test_user = Users(username='test_user_owner', account_id=create_account.account_id, is_owner=True)
    test_user.set_password('test_password')
    db.session.add(test_user)
    db.session.commit()
    return test_user


@pytest.fixture
def create_user(app, create_account):
    test_user = Users(username='test_user_not_owner', account_id=create_account.account_id)
    test_user.set_password('test_password')
    db.session.add(test_user)
    db.session.commit()
    return test_user


@pytest.fixture
def create_account(app):
    test_account = Account(account_name='test_acc_name')
    db.session.add(test_account)
    db.session.commit()
    return test_account


@pytest.fixture
def owner_token(client, create_user_owner):
    response = client.post('/api/auth/login', json={"data": {
        "attributes": {
            "username": create_user_owner.username,
            "password": "test_password"
        }}}, headers={'Content-Type': 'application/vnd.api+json'})

    assert response.status_code == 201
    data = response.get_json()['data']
    return data['token']


@pytest.fixture
def not_owner_token(client, create_user):
    response = client.post('/api/auth/login', json={"data": {
        "attributes": {
            "username": create_user.username,
            "password": "test_password"
        }}}, headers={'Content-Type': 'application/vnd.api+json'})

    assert response.status_code == 201
    data = response.get_json()['data']
    return data['token']
