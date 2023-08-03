from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_migrate import Migrate
import os

database_name = 'PingPhotos.db'
app = Flask(__name__)
app.config['SECRET_KEY'] = '34098-5849yt-3we[0k3299'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_name}'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'images')

images = UploadSet('images', IMAGES)
app.config['UPLOADED_IMAGES_DEST'] = app.config['UPLOAD_FOLDER']
configure_uploads(app, images)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


db = SQLAlchemy()
migrate = Migrate(app, db)

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

from models import User

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

from routes import *

with app.app_context():
    db.create_all()
    db.session.commit()
    print('Created Database!')