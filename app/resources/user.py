
import jwt
import requests
import uuid
from datetime import datetime, timedelta, timezone
from flask import request, render_template, current_app
from flask_jwt_extended import create_access_token
from flask_restful import Resource, reqparse, inputs
from ..models.user import UserModel

from flask_login import login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from ..security import token_required
from sqlalchemy.exc import SQLAlchemyError

class UserRegister(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username',
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )
    parser.add_argument('password',
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )
    parser.add_argument('facebook_id',
        type=str,
        required=False,
        help="This field cannot be left blank!"
    )
    parser.add_argument('profile_photo',
        type=str,
        required=False,
        help="This field cannot be left blank!"
    )
    parser.add_argument('email',
        type=str,
        required=True,
        help="This field cannot be left blank!"
    )

    def post(self):
        data = UserRegister.parser.parse_args()
        user = UserModel.query.filter_by(user_email=data['email']).first()

        if user:
            return {"message": "Email address already exists"}, 400
        
        user = UserModel(user_public_id=str(uuid.uuid4()), username=data["username"], password=generate_password_hash(data["password"], method='pbkdf2:sha256'), facebook_id=data["facebook_id"], profile_photo=data["profile_photo"], email=data["email"], verified=True, credentials="", phone="", user_role="user")

        try:
            user.save_to_db()
        except SQLAlchemyError as e:
            return { "message": f"An error occured inserting user: {str(e)}" }, 500

        return user.json_user(), 201
    

class CheckEmail(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('email',
        type=str,
        required=True,
        help="Email is required"
    )

    def post(self):
        data = CheckEmail.parser.parse_args()
        email = data['email']
        user = UserModel.find_by_email(email)
        if user:
            return user.json()
        return {'message': 'User not found.'}, 404


class FacebookLink(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('facebook_id',
        type=str,
        required=True,
        help="Facebook id is required"
    )
    
    def patch(self, id):
        data = FacebookLink.parser.parse_args()
        user = UserModel.find_by_id(id)

        if user is None:
            return {'message': 'User not found.'}, 404
        else:
            facebook_id = data['facebook_id']
            if facebook_id is not None: 
                user.user_facebook_id = facebook_id

        try:
            user.save_to_db()
        except SQLAlchemyError as e:
            return { "message": f"An error occured inserting user: {str(e)}" }, 500
        
        return user.json()


class UserList(Resource):
    # @token_required
    def get(self):
        return [user.json() for user in UserModel.query.all()]


class Login(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('email',
        type=str,
        required=True,
        help="Email cannot be left blank!"
    )
    parser.add_argument('password',
        type=str,
        required=True,
        help="Password cannot be left blank!"
    )

    def post(self):
        data = Login.parser.parse_args()

        try:
            user = UserModel.query.filter_by(user_email=data['email']).first()
        except Exception as e:
            return {"message": "Database error occurred"}, 500

        if not user or not check_password_hash(user.user_password, data['password']):
            return {'message': 'Please check your login details and try again.'}, 401

        # token = jwt.encode({
        #     'user_id': user.user_id,
        #     'exp': datetime.now(timezone.utc) + timedelta(minutes=30)
        # },
        # current_app.config['SECRET_KEY'],
        # algorithm="HS256")
        access_token = create_access_token(identity=user.user_id)

        login_user(user)
        print(f"current_user from login: {str(current_user)}")

        return { 'message': 'Login successful', 'id': current_user.user_id, 'token': access_token }, 200


class Logout(Resource):
    def get(self):
        logout_user()
        return {'message': 'Logout success'}, 201


class UserProfile(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username',
        type=str,
        required=False,
        help="Name is optional"
    )
    parser.add_argument('phone',
        type=str,
        required=False,
        help="Phone is optional"
    )
    parser.add_argument('profile_photo',
        type=str,
        required=False,
        help="Profile photo is optional"
    )

    def get(self, id):
        user = UserModel.find_by_id(id)

        if user:
            return user.json()
        
        return {'message': 'User not found.'}, 404

    def patch(self, id):
        data = UserProfile.parser.parse_args()
        user = UserModel.find_by_id(id)

        if user is None:
            return {'message': 'User not found.'}, 404
        else:
            username = data['username']
            if username is not None:
                user.user_username = username

            phone = data['phone']
            if phone is not None:
                user.user_phone = phone

            profile_photo = data['profile_photo']
            if profile_photo is not None: 
                user.user_profile_photo = profile_photo

        try:
            user.save_to_db()
        except SQLAlchemyError as e:
            return { "message": f"An error occured inserting user: {str(e)}" }, 500
        
        return user.json()


class UserVerification(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('is_verified',
        type=inputs.boolean,
        required=False,
        default=False,
        help="Is verified cannot be left blank!"
    )

    def patch(self, id):
        data = UserVerification.parser.parse_args()
        user = UserModel.find_by_id(id)

        if user is None:
            return {'message': 'User not found.'}, 404
        else:
            is_verified = data['is_verified']
            if is_verified is not None: 
                user.user_verified = is_verified

        try:
            user.save_to_db()
        except SQLAlchemyError as e:
            return { "message": f"An error occured inserting user: {str(e)}" }, 500
        
        return user.json()


class ChangePassword(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('password',
        type=str,
        required=True,
        help="Password cannot be left blank!"
    )
    
    def patch(self, id):
        data = ChangePassword.parser.parse_args()
        user = UserModel.find_by_id(id)

        if user is None:
            return {'message': 'User not found.'}, 404
        else:
            password = data['password']
            if password is not None: 
                user.user_password = generate_password_hash(password)

        try:
            user.save_to_db()
        except SQLAlchemyError as e:
            return { "message": f"An error occured inserting user: {str(e)}" }, 500
        
        return user.json()
    

class ForgotPassword(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('email',
        type=str,
        required=True,
        help="Email is required"
    )
    
    def post(self):
        data = ForgotPassword.parser.parse_args()
        email = data['email']
        user = UserModel.find_by_email(email)

        if user is None:
            return {'message': 'User not found.'}, 404
        else:
            reset_token = jwt.encode({
                'public_id': user.user_public_id,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, current_app.config['SECRET_KEY'])
        
            url = request.host_url + 'reset_password/'

        return {'message': 'Email sent'}, 201


class ResetPassword(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('password',
        type=str,
        required=True,
        help="Password cannot be left blank!"
    )
    
    def patch(self):
        data = ResetPassword.parser.parse_args()
        
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return {'message': 'Token is missing'}, 401
        
        try:
            token_data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            user = UserModel.query.filter_by(user_public_id=token_data['public_id']).first()

            if user is None:
                return {'message': 'User not found.'}, 404
            else:
                password = data['password']
                if password is not None: 
                    user.user_password = generate_password_hash(password)

                try:
                    user.save_to_db()
                except SQLAlchemyError as e:
                    return { "message": f"An error occured inserting user: {str(e)}" }, 500
                
        except jwt.ExpiredSignatureError:
            return {'message': 'Token is invalid'}, 401

        return {'message': 'Password Reset'}, 201
    

class DeleteAccount(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username',
        type=str,
        required=False,
        help="Name is optional"
    )

    def delete(self, id):
        user = UserModel.find_by_id(id)

        if user is None:
            return {'message': 'User not found.'}, 404
        else:
            user.delete_from_db()
        
        return user.json()