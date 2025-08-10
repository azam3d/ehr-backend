from config import Config
from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager
from flask_restful import Api
from flask_jwt_extended import JWTManager
from .extensions import db
from .models.user import UserModel
from .resources.user import UserRegister, UserList, Login, Logout, UserProfile, UserVerification, CheckEmail, ChangePassword, ForgotPassword, ResetPassword, DeleteAccount

# from .config import config_by_name
# from .routes import register_blueprints

def create_app():
    app = Flask(__name__)
    app.debug=True
    # app.config['SERVER_NAME'] = 'localhost:5000'
    app.config["SECRET_KEY"] = "azam123" 
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://azam:H%40cks029@localhost/ehr'
    app.config['SQLALCHEMY_RECORD_QUERIES'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config.from_object(Config)
    # app.config.from_object(config_by_name[config_name])

    CORS(app, resources={r"/*": {"origins": "*"}})
    api = Api(app)
    jwt = JWTManager(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    # register_blueprints(app)

    @app.route("/")
    def hello_world():
        users = UserModel.query.all()
        print([user.user_username for user in users])
        return "<p>Hello, World!</p>"
    
    api.add_resource(UserRegister, '/api/user/register')
    api.add_resource(UserList, '/api/user/list')
    api.add_resource(Login, '/api/user/login')
    api.add_resource(Logout, '/api/user/logout')
    api.add_resource(UserProfile, '/api/user/profile')
    api.add_resource(UserVerification, '/api/user/verify')
    api.add_resource(CheckEmail, '/api/user/check-email')
    api.add_resource(ChangePassword, '/api/user/change-password')
    api.add_resource(ForgotPassword, '/api/user/forgot-password')
    api.add_resource(ResetPassword, '/api/user/reset-password')
    api.add_resource(DeleteAccount, '/api/user/delete-account')

    return app
