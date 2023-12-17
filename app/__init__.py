from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate

db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.config['PORT'] = config_class.PORT
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    from app.api.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")

    from app.api.user import bp as user_bp
    app.register_blueprint(user_bp, url_prefix="/api/user")

    return app
