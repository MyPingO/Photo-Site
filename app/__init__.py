from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_migrate import Migrate
from flask_mail import Mail
import os, stripe

database_name = 'PingPhotos.db'
app = Flask(__name__)
app.config['SECRET_KEY'] = 'os.environ.get("FlaskSecretKey")'
app.config['SECURITY_PASSWORD_SALT'] = app.config['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_name}'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'images')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.environ.get('Email')
app.config['MAIL_PASSWORD'] = os.environ.get('EmailPassword')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

images = UploadSet('images', IMAGES)
app.config['UPLOADED_IMAGES_DEST'] = app.config['UPLOAD_FOLDER']
configure_uploads(app, images)

stripe.api_key = os.environ.get('StripeAPI')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


db = SQLAlchemy()
migrate = Migrate(app, db)

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

from .models import User

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

from .routes import *

with app.app_context():
    db.create_all()
    db.session.commit()
    print('Created Database!')