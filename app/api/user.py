from app import db
from app.models import Users, Account
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, current_user

bp = Blueprint('user', __name__)


@bp.route('/invite', methods=['POST'])
@jwt_required()
def invite():
    data = request.get_json()

    attributes = data.get('data', {}).get('attributes', {})
    new_username = attributes.get('new_username')

    if not attributes or not new_username:
        return jsonify({"errors": [{
            "status": "400",
            "detail": "Invalid syntax"
        }]}), 400

    if not current_user.is_owner:
        return jsonify({"errors": [{
            "status": "403",
            "detail": "User must be an owner to invite other users"
        }]}), 403

    existing_user = Users.query.filter_by(username=new_username).first()
    if existing_user:
        return jsonify({"errors": [{
            "status": "422",
            "detail": "User already exists"
        }]}), 422

    temp_password = Users.generate_temp_password()

    new_user = Users(username=new_username, account_id=current_user.account_id)
    new_user.set_password(temp_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"data": {
        "new_username": new_username,
        "temporary_password": temp_password
    }}), 201


# @bp.route('/get_info', methods=['GET'])
# @jwt_required()
# def get_info():
#     account_name = Account.query.filter_by(account_id=current_user.account_id).first().account_name
#     account_id = Account.query.filter_by(account_id=current_user.account_id).first().account_id
#     return jsonify({
#         "data": {
#             "type": "users",
#             "id": current_user.user_id,
#             "attributes": {
#                 "username": current_user.username,
#                 "account_name": account_name
#             },
#             "relationships": {
#                 "account": {
#                     "data": {"type": "accounts", "id": account_id}
#                 }
#             }
#         }
#     })


@bp.route('/get_info/<user_id>', methods=['GET'])
@jwt_required()
def get_info(user_id):
    user = Users.query.filter_by(user_id=user_id).first()
    if user is None:
        return jsonify({'error': 'User not found'}), 404

    account = Account.query.filter_by(account_id=user.account_id).first()
    if account is None:
        return jsonify({'error': 'Account not found'}), 404

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
