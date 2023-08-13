from flask_wtf import FlaskForm
from flask_wtf.file import FileRequired, FileAllowed, DataRequired
from wtforms import SubmitField, StringField, PasswordField, BooleanField, MultipleFileField
from flask_uploads import UploadSet, IMAGES
from wtforms.validators import Length, EqualTo, Email

images = UploadSet('images', IMAGES)

class PhotoUploadForm(FlaskForm):
    photos = MultipleFileField('Upload Photo(s)', validators=[FileAllowed(images), DataRequired()])
    submit = SubmitField('Submit')

class PurchaseSearchForm(FlaskForm):
    search_term = StringField('Search Term', validators=[DataRequired()])
    submit = SubmitField('Search')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign Up')

class EditPhotoForm(FlaskForm):
    description = StringField('Description')
    category = StringField('Category')
    price = StringField('Price')
    submit = SubmitField('Submit')