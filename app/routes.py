from datetime import datetime
from xml.dom import minidom
from flask import jsonify, render_template, flash, send_from_directory, url_for, redirect, request
from flask_login import login_required, current_user, login_user, logout_user
from flask_mail import Message
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from .models import CollectionPurchase, Photo, User, Purchase
from .forms import ContactForm, ForgotPasswordForm, PhotoUploadForm, PurchaseSearchForm, LoginForm, ResetPasswordForm, SignupForm, EditPhotoForm, SubscriptionMessageForm
from app import app, db, mail
from PIL import Image, ImageDraw, ImageFont, ImageOps
from math import sqrt
from random import shuffle, choice
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from stripe.error import SignatureVerificationError
import re, os, stripe, xml.etree.ElementTree as ET

collection_categories = ['Flowers & Plants', 'Animals', 'Birds', 'Bugs', 'Vehicles', 'Landscapes', 'Food', 'People', 'Architecture', 'Other']
collection_price = 19.99

# two decorators, same function
@app.route('/')
@app.route('/gallery')
def gallery():
    photos = Photo.query.all()
    shuffle(photos)
    return render_template('gallery.html', title='Gallery', photos=photos)

@app.route('/gallery/<photo_id>', defaults={'photo_description': None})
@app.route('/gallery/<photo_id>_<photo_description>')
def photo_detail(photo_id, photo_description):
    photo = Photo.query.get(photo_id)
    if photo is None:
        flash('Photo not found')
        return redirect(url_for('gallery'))
    
    original_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'originals', photo.filename)
    with Image.open(original_image_path) as img:
        camera_make = img.getexif().get(271)
        camera_model = img.getexif().get(272)
        exif_data = getattr(img, '_getexif', None)()
        date_taken = None
        exposure_time = None
        focal_length = None
        aperture = None
        iso = None
        if exif_data:
            date_taken = exif_data.get(36867) or exif_data.get(36868)
            exposure_time = exif_data.get(33434)
            focal_length = exif_data.get(37386)
            aperture = exif_data.get(37378)
            iso = exif_data.get(34855)

        #convert date taken to datetime object in 12 hour format
        date_taken = datetime.strptime(date_taken, '%Y:%m:%d %H:%M:%S').strftime('%m/%d/%Y %I:%M %p') if date_taken else None

        exif_transpose = ImageOps.exif_transpose(img)
        dimesnions = exif_transpose.size

        img_info = {
            "Dimensions": f"{dimesnions[0]} x {dimesnions[1]}",
            "Format": img.format,
            "Mode": img.mode,
            "Size": f"{round(os.path.getsize(original_image_path) / 1024)} KB",
            "Camera": f"{camera_make} {camera_model}" if camera_make and camera_model else None,
            "Exposure Time": f"{exposure_time.numerator}/{exposure_time.denominator} sec" if exposure_time else None,
            "Focal Length": f"{focal_length}mm" if focal_length else None,
            "Aperture": f"f/{aperture}" if aperture else None,
            "ISO": iso,
            "Date Taken": date_taken,
        }
    
    photo.views += 1
    db.session.commit()
    
    return render_template('photo_details.html', photo=photo, img_info=img_info, title=photo_description)

@app.route('/collections')
def collections():
    categories = db.session.query(Photo.category.distinct()).all()
    categories = [category[0] for category in categories]

    # Getting a random image for each category
    random_images = {}
    for category in categories:
        photos = Photo.query.filter_by(category=category).all()
        random_images[category] = choice(photos) if photos else None

    return render_template('collections.html', categories=categories, random_images=random_images, collection_price=collection_price, title='Collections')

@app.route('/collection/<category>')
def collection(category):
    photos = Photo.query.filter_by(category=category).all()
    shuffle(photos)
    collection_purchased = None
    if current_user.is_authenticated:
        collection_purchased = True if CollectionPurchase.query.filter_by(category=category, user_id=current_user.id).first() else False
    return render_template('collection.html', photos=photos, category=category, collection_purchased=collection_purchased, title=category)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if not current_user.is_admin:
        flash('You do not have permission to view this page!')
        return redirect(url_for('gallery'))

    watermark_text = "Ping's Photos"

    form = PhotoUploadForm()
    if form.validate_on_submit():
        photos = form.photos.data
        for photo in photos:
            filename = secure_filename(photo.filename)
            filename, extension = os.path.splitext(filename)  # Split the filename and extension
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            unique_filename = f"{filename}_{timestamp}{extension}" # Add timestamp to filename to make it unique

            # Directories
            thumbnail_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'thumbnails')
            preview_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'previews')
            original_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'originals')

            # Save the original image without watermark
            original_path = f"{original_dir}/{unique_filename}"
            photo.save(original_path)

            # Open the original image with Pillow
            with Image.open(original_path) as img:
                img = ImageOps.exif_transpose(img)  # Rotate the image based on EXIF data
                img_rgba = img.convert('RGBA')  # Convert the image to RGBA
                
                # Create a blank RGBA image with the same size as the original image
                watermark = Image.new('RGBA', img.size, (255, 255, 255, 0))
                draw = ImageDraw.Draw(watermark)
                verdana_font_path = os.path.abspath("static/fonts/verdana.ttf")
                font = ImageFont.truetype(verdana_font_path, img.width // 40 if img.width > img.height else img.height // 40)
                
                # Set watermark text positions in 4 corners
                pos1 = (img.width // 20, img.height // 20)
                pos2 = (img.width - img.width // 20, img.height // 20)
                pos3 = (img.width // 20, img.height - img.height // 20)
                pos4 = (img.width - img.width // 20, img.height - img.height // 20)

                text_opacity = 192

                # # # Draw them
                draw.text(pos1, watermark_text, font=font, fill=(255, 255, 255, text_opacity), anchor="la")
                draw.text(pos2, watermark_text, font=font, fill=(255, 255, 255, text_opacity), anchor="ra")
                draw.text(pos3, watermark_text, font=font, fill=(255, 255, 255, text_opacity), anchor="lb")
                draw.text(pos4, watermark_text, font=font, fill=(255, 255, 255, text_opacity), anchor="rb")
                
                # Merge the watermark with the original image
                img = Image.alpha_composite(img_rgba, watermark)

                # Convert the image back to RGB
                watermarked_img = img.convert('RGB')

                # Save the full-size image with watermark
                preview_path = f"{preview_dir}/{unique_filename}"
                watermarked_img.save(preview_path)

                # Resize and save the thumbnail image with watermark
                img_resized = watermarked_img.resize((watermarked_img.width // 4, watermarked_img.height // 4), Image.LANCZOS)
                thumbnail_path = f"{thumbnail_dir}/{unique_filename}"
                img_resized.save(thumbnail_path)

                # Add to database
                new_photo = Photo(
                    category='Other',
                    description='',
                    filename=unique_filename,
                    user_id=current_user.id,
                    width=img.width,
                    height=img.height,
                )
                db.session.add(new_photo)

        db.session.commit()

        flash('File successfully uploaded')
        return redirect(url_for('gallery'))

    return render_template('upload.html', form=form, title='Upload')

def distance(p1, p2):
    return sqrt((p1[0] - p2[0]) ** 2 + (p1[1] - p2[1]) ** 2)

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
    image = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], 'originals', photo.filename))
    image = ImageOps.exif_transpose(image)
    if form.validate_on_submit():
        photo.description = str(form.description.data.strip()) if form.description.data else photo.description
        photo.category = form.category.data if form.category.data else photo.category
        photo.price = form.price.data if form.price.data else photo.price
        photo.width = image.width
        photo.height = image.height
        db.session.commit()
        flash('Photo updated')
        return redirect(url_for('gallery'))
    else:
        return render_template('edit_photo.html', form=form, photo=photo, title='Edit Photo')

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
        # delete file
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], 'thumbnails', photo.filename))
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], 'previews', photo.filename))
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], 'originals', photo.filename))
        flash('Photo deleted')
        return redirect(url_for('gallery'))

@app.route('/create_payment/<product_type>/<product_id>')
def create_payment(product_type, product_id):
    # Check if user is authenticated
    if not current_user.is_authenticated:
        flash('You must be logged in to make a purchase')
        return jsonify({'error': 'Unauthorized'}), 401

    # Initialize common variables
    name = None
    description = None
    unit_amount = None
    success_url = None
    cancel_url = None

    if product_type == 'photo':
        photo = Photo.query.get(product_id)
        if not photo:
            flash('Photo not found')
            return jsonify({'error': "Not Found"}), 401
        elif Purchase.query.filter_by(user_id=current_user.id, photo_id=photo.id).first():
            flash('Photo already purchased')
            return jsonify({'error': "Already Purchased"}), 401
        
        name = 'Photo'
        description = (photo.description or '') + f" (Dimensions: {photo.width}x{photo.height})"
        unit_amount = int(photo.price * 100)
        success_url = url_for('thank_you', _external=True)
        cancel_url = url_for('gallery', _external=True)

    elif product_type == 'collection':
        category_name = product_id
        if category_name not in collection_categories:
            flash('Collection not found')
            return jsonify({'error': "Not Found"}), 401
        elif CollectionPurchase.query.filter_by(user_id=current_user.id, category=category_name).first():
            flash('Collection already purchased')
            return jsonify({'error': "Already Purchased"}), 401

        name = 'Collection: ' + category_name
        description = 'This buys all present and future photos in this collection'
        unit_amount = int(round(collection_price * 100))
        success_url = url_for('thank_you', category_name=category_name, _external=True)
        cancel_url = url_for('collections', _external=True)

    else:
        flash('Invalid product')
        return redirect(url_for('gallery'))
    # Create a Stripe session for payment using the defined variables
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'usd',
                'product_data': {
                    'name': name,
                    'description': description + ". Watermarks will be removed from purchased photos",
                },
                'unit_amount': unit_amount,
            },
            'quantity': 1,
        }],
        metadata={
            'user_id': current_user.id,
            'product_type': product_type,
            'product_id': product_id
        },
        mode='payment',
        success_url=success_url,
        cancel_url=cancel_url
    )

    return jsonify(session_id=session.id)

@app.route('/thank_you')
@login_required
def thank_you():
    return render_template('thank_you.html', title='Thank You')


@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    endpoint_secret = os.environ.get('StripeWebhookSecret')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except SignatureVerificationError:
        return 'Signature verification failed', 400

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        product_type = session['metadata']['product_type']
        product_id = session['metadata']['product_id']
        user_id = session['metadata']['user_id']

        if product_type == 'photo':
            success, message = purchase_photo(product_id, user_id)
        elif product_type == 'collection':
            success, message = purchase_collection(product_id, user_id)

        if not success:
            # Handle the error case, maybe log the message
            return message, 400

    return 'Success', 200

def purchase_photo(photo_id, user_id):
    # Check if photo exists
    photo = Photo.query.get(photo_id)
    if not photo:
        return False, 'Photo not found'
    if Purchase.query.filter_by(user_id=user_id, photo_id=photo.id).first():
        return False, 'Photo already purchased'

    new_purchase = Purchase(user_id=user_id, photo_id=photo.id)
    db.session.add(new_purchase)
    db.session.commit()

    return True, 'Photo purchased successfully'

def purchase_collection(category_name, user_id):
    # Check if collection exists
    if category_name not in collection_categories:
        return False, 'Collection not found'

    if CollectionPurchase.query.filter_by(user_id=user_id, category=category_name).first():
        return False, 'Collection already purchased'

    new_collection_purchase = CollectionPurchase(user_id=user_id, category=category_name)
    db.session.add(new_collection_purchase)
    db.session.commit()

    return True, 'Collection purchased successfully'

@app.route('/my_photos')
@login_required
def my_photos():
    # Query individual photo purchases
    purchases = Purchase.query.filter_by(user_id=current_user.id).all()
    purchased_photos = [purchase.photo for purchase in purchases]

    # Query collection purchases and add all photos from those collections
    collection_purchases = CollectionPurchase.query.filter_by(user_id=current_user.id).all()
    for collection_purchase in collection_purchases:
        collection_photos = Photo.query.filter_by(category=collection_purchase.category).all()
        purchased_photos.extend(collection_photos)

    # Remove duplicates if necessary (you can customize this based on your needs)
    purchased_photos = list(set(purchased_photos))

    return render_template('my_photos.html', title='My Photos', photos=purchased_photos)

@app.route('/download/<int:photo_id>')
@login_required
def download(photo_id):
    # Check if photo exists
    photo = Photo.query.get(photo_id)
    if not photo:
        flash('Photo not found')
        return redirect(url_for('gallery'))

    # Check if user has purchased photo
    purchased = Purchase.query.filter_by(user_id=current_user.id, photo_id=photo.id).first() or CollectionPurchase.query.filter_by(user_id=current_user.id, category=photo.category).first()
    if not purchased and not current_user.is_admin:
        flash('You have not purchased this photo')
        return redirect(url_for('gallery'))

    # Download the photo
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'originals'), photo.filename, as_attachment=True)

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

    return render_template('login.html', form=form, title='Login')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        subscribe = form.subscribe.data

        account_validation = check_signup_data(username, email, password)

        if account_validation == False:
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, subscribed=subscribe)

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user, form.remember.data)
        return redirect(url_for('gallery'))

    return render_template('signup.html', form=form, title='Signup')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_reset_token(email)
            send_reset_email(email, token)

        flash("If an account with that email exists, an email has been sent with instructions to reset your password <br> <small>Please check your spam folder if you don't see an email in your inbox</small>", 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form, title='Forgot Password')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except SignatureExpired:
        flash('The reset link has expired', 'warning')
        return redirect(url_for('login'))
    except:
        flash('Something went wrong, please try again with another link', 'warning')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    
    if user is None:
        flash('Invalid reset link', 'warning')
        return redirect(url_for('login'))

    form = ResetPasswordForm()
    
    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash('Passwords do not match', 'warning')
            return redirect(url_for('reset_password', token=token))
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$', form.password.data):
            flash('Password is not strong enough', 'warning')
            return redirect(url_for('reset_password', token=token))
        user.password = generate_password_hash(form.password.data) # You might need to hash this password before saving
        db.session.commit()
        flash('Your password has been reset!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, title='Reset Password')

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def send_reset_email(email, token):
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message('Reset Your Password', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"""
    A request has been made to reset your password for Ping's Photos.
    Click the following link to reset your password: {reset_url}
    If you did not make this request then simply ignore this email and no changes will be made.
    """
    msg.html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                }}
                .content {{
                    max-width: 600px;
                    margin: auto;
                }}
                a {{
                    color: #007bff;
                    text-decoration: none;
                }}
            </style>
        </head>
        <body>
            <div class="content">
                <p>A request has been made to reset your password for <strong>Ping's Photos</strong>.</p>
                <p><a href="{reset_url}">Click here</a> to reset your password.</p>
                <p>If you did not make this request then simply ignore this email and no changes will be made.</p>
            </div>
        </body>
        </html>
    """
    mail.send(msg)

@app.route('/send_subscription_message', methods=['GET', 'POST'])
def send_subscription_message():
    form = SubscriptionMessageForm()
    latest_photos = Photo.query.order_by(Photo.id.desc()).limit(10).all()  # Replace with your logic to get the latest photos

    if form.validate_on_submit():
        title = form.message_title.data
        body = form.message_body.data

        # Send emails (Your existing logic)
        send_update_email(title, body)

        flash('Subscription message sent successfully.', 'success')
        return redirect(url_for('admin'))

    return render_template('subscribe_message.html', form=form, latest_photos=latest_photos, title='Send Subscription Message')

def generate_unsubscribe_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=os.environ.get('UnsubscribeSalt'))

def send_update_email(title, body):
    users = User.query.filter_by(subscribed=True).all()
    for user in users:
        msg = Message(title, sender=app.config['MAIL_USERNAME'], recipients=[user.email])
        msg.subject = title

        # Convert Markdown-style links to HTML links
        body_html = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2">\1</a>', body)
        # Replace newline characters with <br> for HTML
        body_html = body_html.replace('\n', '<br>')
        msg.html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    .email {{
                        font-family: Arial, sans-serif;
                        margin: 20px;
                        text-align: center;
                    }}
                    .content {{
                        margin: auto;
                        font-size: 20px;
                    }}
                    .footer {{
                        margin-top: 20px;
                        font-size: 16px;
                    }}
                    a {{
                        color: #007bff;
                        text-decoration: none;
                    }}
                </style>
            </head>
            <body>
                <div class="email">
                    <div class="content">
                        <p>{body_html}</p>
                    </div>
                    <div class="footer">
                        <p>If you do not want to receive these emails, you can <a href="{url_for('unsubscribe', token=generate_unsubscribe_token(user.email), _external=True)}">unsubscribe</a>.</p>
                    </div>
                </div>
            </body>
            </html>
        """
        mail.send(msg)

@app.route('/unsubscribe/<token>')
def unsubscribe(token):
    unsubscribe_salt = os.environ.get('UnsubscribeSalt')
    print(unsubscribe_salt)
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    try:
        email = serializer.loads(token, salt=unsubscribe_salt)
    except SignatureExpired:
        flash('The unsubscribe link has expired', 'warning')
        return redirect(url_for('gallery'))
    except:
        flash('Something went wrong, please try again with another link', 'warning')
        return redirect(url_for('gallery'))
    
    user = User.query.filter_by(email=email).first()
    
    if user is None:
        flash('Invalid unsubscribe link', 'warning')
        return redirect(url_for('gallery'))

    user.subscribed = False
    db.session.commit()
    flash('You have been unsubscribed from our mailing list', 'success')
    return redirect(url_for('gallery'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    # Ensure that only admins can access this page
    if not current_user.is_admin:
        return redirect(url_for('gallery'))

    users = User.query.all()
    purchases = Purchase.query.all()
    collection_purchases = CollectionPurchase.query.all()

    # Handle editing user information
    if request.method == 'POST':
        user_id = request.form['user_id']
        user = User.query.get(user_id)
        if user:
            user.username = request.form['username']
            user.email = request.form['email']
            # Other fields you want to edit
            db.session.commit()

    return render_template('admin.html', users=users, purchases=purchases, collection_purchases=collection_purchases, title='Admin')

@app.route('/admin/search_purchases', methods=['GET', 'POST'])
@login_required
def search_purchases():
    if not current_user.is_admin:
        flash('You do not have permission to view this page!')
        return redirect(url_for('gallery'))

    form = PurchaseSearchForm()
    purchases = []
    if form.validate_on_submit():
        search_term = form.search_term.data
        purchases = Purchase.query.join(User).filter(
            User.username.contains(search_term)
        ).all()
    return render_template('search_purchases.html', form=form, purchases=purchases, title='Search Purchases')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('gallery'))

def check_signup_data(username, email, password) -> bool:

    details_valid = True

    # Check if username is already taken
    user = User.query.filter_by(username=username).first()
    if user:
        flash('Username already taken')
        details_valid = False
    # Check if email is already taken
    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email already taken')
        details_valid = False
    # Check if password is not strong enough
    # must have at least 8 characters, one uppercase, one lowercase, one number, and one special character
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$', password):
        flash('Password is not strong enough')
        details_valid = False
    
    return details_valid

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        subject = form.subject.data
        sender_email = 'contact.pingsphotos@gmail.com' # Your email
        user_email = form.email.data
        message_body = f"From: {form.name.data} <{user_email}>\n\nMessage:\n{form.message.data}"

        msg = Message(subject, sender=sender_email, recipients=[sender_email])
        msg.body = message_body
        msg.reply_to = user_email # Set reply-to to the user's email

        mail.send(msg)

        flash('An email has been sent to Ping\'s Photos. We will get back to you as soon as possible!', 'success')
        return redirect(url_for('gallery'))  # Redirect to home or any other page

    return render_template('contact.html', form=form, title='Contact')

@app.route('/about')
def about():
    return render_template('about.html', title='About')

@app.route('/sitemap')
@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('static', 'sitemap.xml')

@app.route('/google-merchant-feed.xml')
def google_merchant_feed():
    # Create the root element
    rss = ET.Element('rss', {'version': '2.0', 'xmlns:g': 'http://base.google.com/ns/1.0'})
    channel = ET.SubElement(rss, 'channel')

    # Add basic channel info
    ET.SubElement(channel, 'title').text = "Ping's Photos"
    ET.SubElement(channel, 'link').text = 'http://www.pingsphotos.com'
    ET.SubElement(channel, 'description').text = 'Your photo marketplace'

    products = Photo.query.all()  # Replace with your own query logic to get products

    for product in products:
        item = ET.SubElement(channel, 'item')
        ET.SubElement(item, 'g:id').text = str(product.id)
        ET.SubElement(item, 'g:title').text = product.description
        ET.SubElement(item, 'g:description').text = product.description
        ET.SubElement(item, 'g:link').text = f'http://www.pingsphotos.com/gallery/{product.id}'
        ET.SubElement(item, 'g:price').text = f'{product.price} USD'
        ET.SubElement(item, 'g:availability').text = 'in stock'
        ET.SubElement(item, 'g:condition').text = 'new'
    
    # Prettify the XML
    rough_string = ET.tostring(rss, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    pretty_xml_str = reparsed.toprettyxml(indent="\t")

    # Save the XML content to a file
    xml_file_path = os.path.join(app.root_path, 'static', 'google-merchant-feed.xml')
    with open(xml_file_path, 'w') as f:
        f.write(pretty_xml_str)

    # Serve the XML file
    return send_from_directory('static', secure_filename('google-merchant-feed.xml'),
                               as_attachment=True, mimetype='application/xml')
