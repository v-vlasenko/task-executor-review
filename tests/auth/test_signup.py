def test_successful_signup(client):
    response = client.post('/api/auth/signup', json={
        'data': {
            'attributes': {
                'username': 'test_user',
                'password': 'test_password',
                'account_name': 'test_account'
            }
        }
    }, headers={'Content-Type': 'application/vnd.api+json'})

    assert response.status_code == 201
    data = response.get_json()['data']
    assert 'id' in data
    assert 'token' in data['attributes']


def test_with_existing_user(client, create_user_owner):
    response = client.post('/api/auth/signup', json={
        'data': {
            'attributes': {
                'username': f'{create_user_owner.username}',
                'password': 'test_password',
                'account_name': 'test_account'
            }
        }
    }, headers={'Content-Type': 'application/vnd.api+json'})

    assert response.status_code == 422
    errors = response.get_json()['errors']
    assert len(errors) == 1
    assert errors[0]['status'] == '422'
    assert errors[0]['detail'] == 'User already exists'


def test_missing_required_fields(client):
    response = client.post('/api/auth/signup', json={
        'data': {
            'attributes': {
                'username': 'test_user_missing_fields'
            }
        }
    }, headers={'Content-Type': 'application/vnd.api+json'})

    assert response.status_code == 422
    errors = response.get_json()['errors']
    assert len(errors) == 1
    assert errors[0]['status'] == '422'
    assert errors[0]['detail'] == 'Required fields: password, account_name'
