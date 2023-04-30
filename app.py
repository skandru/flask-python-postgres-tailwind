from flask import Flask, render_template, request, redirect,url_for, flash, current_app, g
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from forms import RegistrationForm
from forms import LoginForm
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
import datetime
import logging

app = Flask(__name__)

ENV = 'dev'

if ENV == 'dev':
    app.debug = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:CXSbElP{N@localhost/acura'
else:
    app.debug = False
    app.config['SQLALCHEMY_DATABASE_URI'] = ''

app.config['SECRET_KEY'] = 'Roja'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'dd8472badc7d78'
app.config['MAIL_PASSWORD'] = 'd648e65cf25c0a'

mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
logging.basicConfig(level=logging.DEBUG)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_confirmed = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    customer = db.Column(db.String(200), unique=True)
    dealer = db.Column(db.String(200))
    rating = db.Column(db.Integer)
    comments = db.Column(db.Text())

    def __init__(self, customer, dealer, rating, comments):
        self.customer = customer
        self.dealer = dealer
        self.rating = rating
        self.comments = comments

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    return render_template('index.html',current_time=datetime.datetime.now())

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please login or use a different email.', 'danger')
            return redirect(url_for('register'))
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        token = generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        msg = Message('Confirm Your Email Address', sender='from@example.com', recipients=[email])
        msg.body = f'Please click the following link to confirm your email address: {confirm_url}'
        mail.send(msg)
        flash('An email has been sent to your email address. Please confirm your email address to login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email)


@app.route('/confirm-email/<token>')
def confirm_email(token):
    logging.debug('token', token)
    try:
        logging.debug('calling confirm_token')
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    logging.debug('User Record', user)
    if user.is_confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        logging.debug('User Record not confirmed', user.is_confirmed)
        user.is_confirmed = True
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            max_age=expiration
        )
    except:
        return False
    return email

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect(url_for('login'))
        if not user.is_confirmed:
            flash('Please confirm your email address before logging in.', 'warning')
            return redirect(url_for('login'))
        login_user(user)
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return render_template('logout.html')

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/submit_form', methods=['POST'])
def submit_form():
    name = request.form['name']
    email = request.form['email']
    # Do something with the name and email
    return 'Thanks for submitting the form!'
    
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email does not exist. Please try again.', 'danger')
            return redirect(url_for('forgot_password'))
        token = secrets.token_hex(16)
        reset_url = url_for('reset_password', token=token, _external=True)
        msg = Message('Reset Your Password', sender='your-email@gmail.com', recipients=[email])
        msg.body = f'Please click the following link to reset your password: {reset_url}'
        mail.send(msg)
        flash('An email has been sent to your email address. Please follow the instructions in the email to reset your password.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.query.filter_by(reset_password_token=token).first()
    if not user:
        flash('Invalid or expired token. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('reset_password', token=token))
        hashed_password = generate_password_hash(password, method='sha256')
        user.password = hashed_password
        user.reset_password_token = None
        db.session.commit()
        flash('Your password has been updated successfully. Please login with your new password.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')
   

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/users')
def get_users():
    # Get all users from the database
    users = User.query.all()

    # Return the users as a list of dictionaries
    return [{'id': user.id, 'username': user.username, 'email': user.email} for user in users]

@app.route('/users/<int:user_id>')
def get_user(user_id):
    # Get a specific user from the database by ID
    user = User.query.get(user_id)

    if user:
        # Return the user as a dictionary
        return {'id': user.id, 'username': user.username, 'email': user.email}
    else:
        # Return an error message
        return {'error': 'User not found'}

@app.route('/submit', methods=['POST'])
def submit():
    if request.method == 'POST':
        customer = request.form['customer']
        dealer = request.form['dealer']
        rating = request.form['rating']
        comments = request.form['comments']
        if customer == '' or dealer == '':
            return render_template('index.html', message='Please enter required fields')
        # Access Flask application context here
        with app.app_context():
            # Check if feedback record already exists for customer
            if db.session.query(Feedback).filter(Feedback.customer == customer).count() == 0:
                # Create new feedback object and add to database
                data = Feedback(customer, dealer, rating, comments)
                db.session.add(data)
                db.session.commit()
                # Send email notification
                #send_mail(customer, dealer, rating, comments)
                return render_template('success.html')
            else:
                return render_template('index.html', message='You have already submitted feedback')

if __name__ == '__main__':
    app.run()
