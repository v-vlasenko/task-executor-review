from datetime import timedelta
from app import db, jwt
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
from app.models import Users, Account, TokenBlockList

bp = Blueprint('auth', __name__)


@bp.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()

        attributes = data.get('data', {}).get('attributes', {})
        username = attributes.get('username')
        password = attributes.get('password')
        account_name = attributes.get('account_name')

        if not attributes or not username or not password or not account_name:
            return jsonify({'errors': [{
                'status': '422',
                'detail': 'Some attributes are missing. '
                'Username, password and account name are required'
            }]}), 422

        existing_user = Users.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'errors': [{
                'status': '422', 
                'detail': 'User already exists'
            }]}), 422

        existing_account = Account.query.filter_by(account_name=account_name).first()
        if existing_account:
            return jsonify({'errors': [{
                'status': '422', 
                'detail': 'Account name already exists'
            }]}), 422

        new_account = Account(account_name=account_name)
        db.session.add(new_account)
        db.session.commit()

        new_user = Users(username=username, account_id=new_account.account_id, is_owner=True)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        access_token = create_access_token(identity=new_user.username, expires_delta=timedelta(hours=2))

        return jsonify({
            'data': {
                'id': new_user.user_id,
                'type': 'users',
                'attributes': {
                    'message': 'Users has been successfully created',
                    'token': access_token
                },
                'relationships': {
                    'account': {
                        'data': {
                            'id': new_account.account_id,
                            'type': 'accounts'
                        }
                    }
                }
            }
        }), 201
    except (KeyError, TypeError):
        return jsonify({"errors": [{
            "status": "400", 
            "detail": "Invalid JSON structure"
        }]}), 400


@bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        attributes = data.get('data', {}).get('attributes', {})
        username = attributes.get('username')
        password = attributes.get('password')

        if not data or 'username' not in attributes or 'password' not in attributes:
            return jsonify({'errors': [{
                'status': '422', 
                'detail': 'Username and password are required fields'
            }]}), 422

        if not username or not password:
            return jsonify({'errors': [{
                'status': '422', 
                'detail': 'Username and password are required fields'
            }]}), 422

        user = Users.query.filter_by(username=username).first()
        if not user:
            return ({'errors': [{
                'status': '401', 
                'detail': 'Invalid username or password'
            }]}), 401

        if not user.check_password(password):
            return jsonify({'errors': [{
                'status': '401', 
                'detail': 'Invalid username or password'
            }]}), 401

        if user and user.check_password(password):
            access_token = create_access_token(identity=user.username, expires_delta=timedelta(hours=2))
            return jsonify({'data': {
                'message': 'Users is successfully logged in', 
                'token': access_token
            }}), 201
    except (KeyError, TypeError):
        return jsonify({"errors": [{
            'status': '400', 
            'detail': 'Invalid JSON structure'
        }]}), 400


@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    token = TokenBlockList.query.filter_by(jti=jti).first()
    if token:
        return jsonify({'errors': [{
            'status': '422', 
            'detail': 'Token has been already revoked'
        }]}), 401

    blocklist = TokenBlockList(jti=jti)
    db.session.add(blocklist)
    db.session.commit()
    return jsonify({'data': {
        'message': 'Users is successfully logged out'
    }}), 201


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_data):
    return jsonify({'errors': [{
        'status': '401',
        'title': 'Unauthorized',
        'detail': 'Token is expired'
    }]}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'errors': [{
        'status': '401',
        'title': 'Unauthorized',
        'detail': 'Invalid token, signature verification failed'
    }]}), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'errors': [{
        'status': '401',
        'title': 'Unauthorized',
        'detail': "Request doesn't contain a valid token"
    }]}), 401


@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_data):
    return jsonify({'errors': [{
        'status': '422',
        'detail': 'Token has been already revoked'
    }]}), 422


@jwt.token_in_blocklist_loader
def token_in_blocklist_callback(jwt_header, jwt_data):
    jti = jwt_data['jti']
    token = TokenBlockList.query.filter_by(jti=jti).first()
    return token is not None
