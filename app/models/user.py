
import enum
from ..extensions import db
from flask_login import UserMixin

class Role(enum.Enum):
    admin = 1
    clinician = 2
    user = 3
    
class UserModel(UserMixin, db.Model):
    __tablename__ = 'user'

    user_id = db.Column(db.Integer, primary_key=True)
    user_public_id = db.Column(db.String(45), unique = True)
    user_email = db.Column(db.String(255), unique=True, nullable=False)
    user_username = db.Column(db.String(80), unique=True, nullable=False)
    user_password = db.Column(db.String(255))
    user_facebook_id = db.Column(db.String(80))
    user_verified = db.Column(db.Boolean, default=False)
    user_credentials = db.Column(db.String(80))
    user_profile_photo = db.Column(db.String(255))
    user_phone = db.Column(db.String(255))
    user_role = db.Column(db.Enum(Role))

    def __init__(self, user_public_id, email, username, password, facebook_id, verified, credentials, profile_photo, phone, user_role):
        self.user_public_id = user_public_id
        self.user_email = email
        self.user_username = username
        self.user_password = password
        self.user_facebook_id = facebook_id
        self.user_verified = verified
        self.user_credentials = credentials
        self.user_profile_photo = profile_photo
        self.user_phone = phone
        self.user_role = user_role

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False
    
    def get_id(self):
        return (self.user_id)

    def json_user(self):
        return {
            'id': self.user_id,
            'user_public_id': self.user_public_id,
            'username': self.user_username,
            'email': self.user_email,
            'facebook_id': self.user_facebook_id,
            'verified': self.user_verified,
            'credentials': self.user_credentials,
            'profile_photo': self.user_profile_photo,
            'phone': self.user_phone }

    def json(self):
        return {
            'id': self.user_id,
            'user_public_id': self.user_public_id,
            'username': self.user_username,
            'email': self.user_email,
            'facebook_id': self.user_facebook_id,
            'verified': self.user_verified,
            'credentials': self.user_credentials,
            'profile_photo': self.user_profile_photo,
            'phone': self.user_phone }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(user_id=_id).first()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(user_username=username).first()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(user_email=email).first()
