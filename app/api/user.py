from pydantic import ValidationError
from app import db
from app.models import Users, Account
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, current_user
from app.api.schemas.errors import JsonApiErrorResponse, JsonApiError
from app.api.schemas.user import InviteInputPayload

bp = Blueprint('user', __name__)


@bp.route('/invite', methods=['POST'])
@jwt_required()
def invite():
    try:
        data = request.get_json()
        InviteInputPayload.model_validate(data)
    except ValidationError as e:
        missing_attribute_path = ' -> '.join(map(str, e.errors()[0]['loc']))
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422', detail=f'Missing required attribute: {missing_attribute_path}'
        )])), 422

    attributes = data.get('data', {}).get('attributes', {})
    new_username = attributes.get('new_username')

    if not current_user.is_owner:
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='403',
            detail="User must be an owner to invite other users"
        )])), 403

    existing_user = Users.query.filter_by(username=new_username).first()
    if existing_user:
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='422',
            detail="User already exists"
        )])), 422

    temp_password = Users.generate_temp_password()

    new_user = Users(username=new_username, account_id=current_user.account_id)
    new_user.set_password(temp_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"data": {
        "new_username": new_username,
        "temporary_password": temp_password
    }}), 201


@bp.route('/get_info/<user_id>', methods=['GET'])
@jwt_required()
def get_info(user_id):
    user = Users.query.filter_by(user_id=user_id).first()
    if user is None:
        return jsonify(JsonApiErrorResponse(errors=[JsonApiError(
            status='404',
            detail="User not found"
        )])), 404

    account = Account.query.filter_by(account_id=user.account_id).first()

    return jsonify({
        "data": {
            "type": "users",
            "id": user.user_id,
            "attributes": {
                "username": user.username,
                "account_name": account.account_name
            },
            "relationships": {
                "account": {
                    "data": {"type": "accounts", "id": account.account_id}
                }
            }
        }
    })
