from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, DataRequired
from wtforms import SubmitField, StringField, PasswordField, BooleanField, MultipleFileField, SelectField, TextAreaField
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
    category = SelectField('Category', choices=[('',''), ('Flowers & Plants', 'Flowers & Plants'), ('Birds', 'Birds'), ('Animals', 'Animals'), ('Bugs', 'Bugs'), ('Landscapes', 'Landscapes'), ('People', 'People'), ('Food', 'Food'), ('Architecture', 'Architecture'), ('Other', 'Other')])
    price = StringField('Price')
    submit = SubmitField('Submit')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject')
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit')