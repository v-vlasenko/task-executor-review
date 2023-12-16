from datetime import timedelta
from app import db, jwt, Config
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
from app.models import Users, Account, TokenBlockList
from app.api.errors import JsonApiErrorResponse, JsonApiError

bp = Blueprint('auth', __name__)


@bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    if not data.get('data', {}):
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422', detail="Required field: data")])), 422

    attributes = data.get('data', {}).get('attributes', {})
    if not attributes:
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422', detail="Required field: attributes")])), 422

    username = attributes.get('username')
    password = attributes.get('password')
    account_name = attributes.get('account_name')

    missing_attributes = [attr for attr in ['username', 'password', 'account_name'] if attr not in attributes]
    if missing_attributes:
        missing_attributes_str = ', '.join(missing_attributes)
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422',
            detail=f'Required field{"s" if len(missing_attributes) > 1 else ""}: {missing_attributes_str}'
        )])), 422

    existing_user = Users.query.filter_by(username=username).first()
    if existing_user:
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422', detail=f'User already exists')])), 422

    new_account = Account(account_name=account_name)
    db.session.add(new_account)
    db.session.commit()

    new_user = Users(username=username, account_id=new_account.account_id, is_owner=True)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=new_user.username,
                                       expires_delta=timedelta(hours=Config.TOKEN_EXPIRATION_HOURS))

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


@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data.get('data', {}):
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422', detail="Required field: data")])), 422

    attributes = data.get('data', {}).get('attributes', {})
    if not attributes:
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422', detail="Required field: attributes")])), 422

    username = attributes.get('username')
    password = attributes.get('password')

    required_attributes = ['username', 'password']
    missing_attributes = [attr for attr in required_attributes if attr not in attributes]
    if missing_attributes:
        missing_attributes_str = ', '.join(missing_attributes)
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422',
            detail=f'Required field{"s" if len(missing_attributes) > 1 else ""}: '
                   f'{missing_attributes_str}'
        )])), 422

    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='401',
            detail='Invalid username or password'
        )])), 401

    if not user.check_password(password):
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='401',
            detail='Invalid username or password'
        )])), 401

    if user and user.check_password(password):
        access_token = create_access_token(identity=user.username,
                                           expires_delta=timedelta(hours=Config.TOKEN_EXPIRATION_HOURS))
        return jsonify({'data': {
            'message': 'Users is successfully logged in',
            'token': access_token
        }}), 201


@bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    token = TokenBlockList.query.filter_by(jti=jti).first()
    if token:
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422',
            detail='Token has been already revoked'
        )])), 422

    blocklist = TokenBlockList(jti=jti)
    db.session.add(blocklist)
    db.session.commit()
    return jsonify({'data': {'message': 'Users is successfully logged out'}}), 201


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_data):
    return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
        status='401',
        detail='Token is expired'
    )])), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
        status='401',
        detail='Invalid token, signature verification failed'
    )])), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
        status='401',
        detail="Request doesn't contain a valid token"
    )])), 401


@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_data):
    return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
        status='422',
        detail="Token has been already revoked"
    )])), 422


@jwt.token_in_blocklist_loader
def token_in_blocklist_callback(jwt_header, jwt_data):
    jti = jwt_data['jti']
    token = TokenBlockList.query.filter_by(jti=jti).first()
    return token is not None
