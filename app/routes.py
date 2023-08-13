from datetime import datetime
from flask import jsonify, render_template, flash, send_from_directory, url_for, redirect, request, abort
from flask_login import login_required, current_user, login_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from .models import Photo, User, Purchase
from .forms import PhotoUploadForm, PurchaseSearchForm, LoginForm, SignupForm, EditPhotoForm
from app import app, db
import re, os, stripe

# two decorators, same function
@app.route('/')
@app.route('/gallery')
def gallery():
    photos = Photo.query.all()
    return render_template('gallery.html', title='Gallery', photos=photos)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if not current_user.is_admin:
        flash('You do not have permission to view this page!')
        return redirect(url_for('gallery'))

    form = PhotoUploadForm()
    if form.validate_on_submit():
        photos = form.photos.data
        for photo in photos:
            filename = secure_filename(photo.filename)
            filename, extension = os.path.splitext(filename)  # Split the filename and extension
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            unique_filename = f"{filename}_{timestamp}{extension}" # Add timestamp to filename to make it unique
            filepath = f"{app.config['UPLOAD_FOLDER']}/{unique_filename}"
            photo.save(filepath)
            new_photo = Photo(filename=unique_filename, user_id=current_user.id)
            db.session.add(new_photo)
        
        db.session.commit()

        flash('File successfully uploaded')
        return redirect(url_for('gallery'))

    return render_template('upload.html', form=form)

@app.route('/edit_photo/<int:photo_id>', methods=['GET', 'POST'])
@login_required
def edit_photo(photo_id):
    if not current_user.is_admin:
        flash('You do not have permission to view this page!')
        return redirect(url_for('gallery'))
    
    photo = Photo.query.get(photo_id)
    if not photo:
        flash('Photo not found')
        return redirect(url_for('gallery'))
    
    form = EditPhotoForm()
    if form.validate_on_submit():
        photo.description = form.description.data if form.description.data else photo.description
        photo.category = form.category.data if form.category.data else photo.category
        photo.price = form.price.data if form.price.data else photo.price
        db.session.commit()
        flash('Photo updated')
        return redirect(url_for('gallery'))
    else:
        return render_template('edit_photo.html', form=form, photo=photo)

    
@app.route('/delete_photo/<int:photo_id>', methods=['POST'])
@login_required
def delete_photo(photo_id):
    if not current_user.is_admin:
        flash('You do not have permission to view this page!')
        return redirect(url_for('gallery'))
    
    photo = Photo.query.get(photo_id)
    if not photo:
        flash('Photo not found')
        return redirect(url_for('gallery'))
    else:
        db.session.delete(photo)
        db.session.commit()
        flash('Photo deleted')
        return redirect(url_for('gallery'))

@app.route('/admin/search_purchases', methods=['GET', 'POST'])
@login_required
def search_purchases():
    if not current_user.is_admin:
        abort(403, "You do not have permission to view this page!")  # Return HTTP 403 if user is not admin

    form = PurchaseSearchForm()
    purchases = []
    if form.validate_on_submit():
        search_term = form.search_term.data
        purchases = Purchase.query.join(User).filter(
            User.username.contains(search_term)
        ).all()
    return render_template('search_purchases.html', form=form, purchases=purchases)

@login_required
@app.route('/purchase/<int:photo_id>')
def purchase(photo_id):
    # Check if photo exists
    photo = Photo.query.get(photo_id)
    if not photo:
        flash('Photo not found')
        return redirect(url_for('gallery'))
    if Purchase.query.filter_by(user_id=current_user.id, photo_id=photo.id).first():
        flash('Photo already purchased')
        return redirect(url_for('gallery'))

    new_purchase = Purchase(user_id=current_user.id, photo_id=photo.id)

    db.session.add(new_purchase)
    db.session.commit()

    flash('Photo purchased successfully, you can now download it from the My Photos page')
    return redirect(url_for('gallery'))

@app.route('/create_payment/<int:photo_id>')
@login_required
def create_payment(photo_id):
    # Check if photo is already purchased
    purchase = Purchase.query.filter_by(user_id=current_user.id, photo_id=photo_id).first()
    if purchase:
        flash('You have already purchased this photo')
        return redirect(url_for('gallery'))

    photo = Photo.query.get(photo_id)
    if not photo:
        return "Photo not found", 404
    
    # Create a Stripe session for payment
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'product_data': {
                    'name': 'Photo',
                },
                'unit_amount': int(photo.price * 100),
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('purchase', photo_id=photo_id, _external=True, _scheme='http', _host='localhost:5000'),
        cancel_url=url_for('gallery', _external=True, _scheme='http', _host='localhost:5000')
    )

    return jsonify(session_id=session.id)

@login_required
@app.route('/my_photos')
def my_photos():
    purchases = Purchase.query.filter_by(user_id=current_user.id).all()
    purchased_photos = [purchase.photo for purchase in purchases]  # gather all photos related to these purchases
    return render_template('my_photos.html', title='My Photos', photos=purchased_photos)

@login_required
@app.route('/download/<int:photo_id>')
def download(photo_id):
    # Check if photo exists
    photo = Photo.query.get(photo_id)
    if not photo:
        return "Photo not found", 404

    # Check if user has purchased photo
    purchase = Purchase.query.filter_by(user_id=current_user.id, photo_id=photo.id).first()
    if not purchase:
        flash('You have not purchased this photo')
        return redirect(url_for('gallery'))

    # Download the photo
    return send_from_directory(app.config['UPLOAD_FOLDER'], photo.filename, as_attachment=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user, form.remember.data)
            return redirect(url_for('gallery'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        check_signup_data(username, email, password)

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user, form.remember.data)
        return redirect(url_for('gallery'))

    return render_template('signup.html', form=form)

def check_signup_data(username, email, password):
    # Check if username is already taken
    user = User.query.filter_by(username=username).first()
    if user:
        flash('Username already taken')
        return redirect(url_for('signup'))
    # Check if email is already taken
    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email already taken')
        return redirect(url_for('signup'))
    # Check if password is not strong enough
    # must have at least 8 characters, one uppercase, one lowercase, one number, and one special character
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$', password):
        flash('Password is not strong enough')
        return redirect(url_for('signup'))
    
