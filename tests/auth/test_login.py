def test_login(client, create_user_owner):
    response = client.post('/api/auth/login', headers={
        'Content-Type': 'application/vnd.api+json'
    }, json={
        'data': {
            'attributes': {
                'username': 'test_user_owner',
                'password': 'test_password'
            }}})

    assert response.status_code == 201
    data = response.get_json()['data']
    assert 'token' in data
    assert 'Users is successfully logged in' in data['message']


def test_invalid_password(client, create_user_owner):
    response = client.post('/api/auth/login', headers={
        'Content-Type': 'application/vnd.api+json'
    }, json={
        'data': {
            'attributes': {
                'username': 'test_user_owner',
                'password': 'test'
            }}})

    assert response.status_code == 401
    errors = response.get_json()['errors']
    assert len(errors) == 1
    assert errors[0]['status'] == '401'
    assert errors[0]['detail'] == 'Invalid username or password'


def test_invalid_username(client, create_user_owner):
    response = client.post('/api/auth/login', headers={
        'Content-Type': 'application/vnd.api+json'
    }, json={
        'data': {
            'attributes': {
                'username': 'test_invalid',
                'password': 'test_password'
            }}})

    assert response.status_code == 401
    errors = response.get_json()['errors']
    assert len(errors) == 1
    assert errors[0]['status'] == '401'
    assert errors[0]['detail'] == 'Invalid username or password'


def test_missing_username_or_password(client):
    response = client.post('/api/auth/login', headers={
        'Content-Type': 'application/vnd.api+json'
    }, json={
        'data': {
            'attributes': {
                'password': 'test_password'
            }}})

    assert response.status_code == 422
    errors = response.get_json()['errors']
    assert len(errors) == 1
    assert errors[0]['status'] == '422'
    assert errors[0]['detail'] == 'Username and password are required fields'


def test_user_not_found(client):
    response = client.post('/api/auth/login', headers={
        'Content-Type': 'application/vnd.api+json'
    }, json={
        'data': {
            'attributes': {
                'username': 'nonexistent_user',
                'password': 'test_password'
            }}})

    assert response.status_code == 401
    errors = response.get_json()['errors']
    assert len(errors) == 1
    assert errors[0]['status'] == '401'
    assert errors[0]['detail'] == 'Invalid username or password'
