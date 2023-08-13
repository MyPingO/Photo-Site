from flask_sqlalchemy import SQLAlchemy, Model
from flask_login import LoginManager, UserMixin
from datetime import datetime

from app import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))
    photos = db.relationship('Photo', backref='owner', lazy='dynamic')
    purchases = db.relationship('Purchase', back_populates='user', lazy='dynamic')
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Photo(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(80))
    description = db.Column(db.String(80))
    filename = db.Column(db.String(80), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    price = db.Column(db.Float, default=1.99)
    purchases = db.relationship('Purchase', back_populates='photo', lazy='dynamic')

    def __repr__(self):
        return f'<Photo {self.filename}>'

class Purchase(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    photo_id = db.Column(db.Integer, db.ForeignKey('photo.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.DateTime, default=datetime.now())

    user = db.relationship('User', back_populates='purchases', lazy=True)
    photo = db.relationship('Photo', back_populates='purchases', lazy=True)

    def __repr__(self):
        return f'<Purchase {self.id}>'
    def date_pretty(self):
        return self.date.strftime('%b %d, %Y %I:%M %p')

