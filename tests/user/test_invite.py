def test_successful_invite(client, create_user_owner, owner_token):
    response = client.post('/api/user/invite', json={
        'data': {'attributes': {
            'new_username': 'new_user'
        }}}, headers={
        'Content-Type': 'application/vnd.api+json',
        'Authorization': f'Bearer {owner_token}'
    })

    assert response.status_code == 201
    data = response.get_json()['data']
    assert 'new_username' in data
    assert 'temporary_password' in data


def test_invite_not_by_owner(client, create_user, not_owner_token):
    response = client.post('/api/user/invite', json={
        'data': {'attributes': {
            'new_username': 'new_user'
        }}}, headers={
        'Content-Type': 'application/vnd.api+json',
        'Authorization': f'Bearer {not_owner_token}'
    })

    assert response.status_code == 403
    errors = response.get_json()['errors']
    assert errors[0]['status'] == '403'
    assert errors[0]['detail'] == 'User must be an owner to invite other users'


def test_existing_user_invite(client, create_user_owner, owner_token, create_user):
    response = client.post('/api/user/invite', json={
        'data': {'attributes': {
            'new_username': create_user.username
        }}}, headers={
        'Content-Type': 'application/vnd.api+json',
        'Authorization': f'Bearer {owner_token}'
    })

    assert response.status_code == 422
    errors = response.get_json()['errors']
    assert errors[0]['status'] == '422'
    assert errors[0]['detail'] == 'User already exists'


def test_invite_unauthorized(client, create_user_owner, owner_token):
    response = client.post('/api/user/invite', json={
        'data': {'attributes': {
            'new_username': 'new_user'
        }}}, headers={
        'Content-Type': 'application/vnd.api+json'
    })
    assert response.status_code == 401

