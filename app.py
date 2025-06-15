import os, requests
import random
import string
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from user_agents import parse

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)


# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=False)  # Active after OTP verification
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    otp = db.Column(db.String(6))
    otp_created_at = db.Column(db.DateTime)
    login_activities = db.relationship('LoginActivity', backref='user', lazy=True, order_by='desc(LoginActivity.login_time)')

    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def increment_login_attempts(self):
        self.login_attempts += 1
        if self.login_attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
            self.locked_until = datetime.utcnow() + timedelta(
                minutes=app.config['LOGIN_LOCKOUT_MINUTES'])
        db.session.commit()
    
    def reset_login_attempts(self):
        self.login_attempts = 0
        self.locked_until = None
        db.session.commit()
    
    def is_locked(self):
        return self.locked_until and self.locked_until > datetime.utcnow()
    
    def is_otp_expired(self):
        if not self.otp_created_at:
            return True
        return datetime.utcnow() > self.otp_created_at + timedelta(seconds=app.config['OTP_EXPIRATION'])
    

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    browser = db.Column(db.String(100), nullable=False)
    device = db.Column(db.String(100))
    location = db.Column(db.String(200))  # Increased length
    platform = db.Column(db.String(50))
    postal_code = db.Column(db.String(20))  # New field
    city = db.Column(db.String(100))       # New field
    region = db.Column(db.String(100))     # New field
    country = db.Column(db.String(100))    # New field
    success = db.Column(db.Boolean)        # Existing field
    status = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    isp = db.Column(db.String(100))
    # Existing field

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', 
                                  validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user and user.email_verified:
            raise ValidationError('Email already registered.')

class VerifyRegistrationForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify ')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset OTP')

class VerifyOTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify OTP')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', 
                                  validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

# Helper functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(user, purpose='registration'):
    otp = generate_otp()
    user.otp = otp
    user.otp_created_at = datetime.utcnow()
    db.session.commit()
    
    subject = "Your Verification OTP"
    if purpose == 'registration':
        body = f"""Your registration OTP is: {otp}
        
This OTP is valid for 5 minutes. Enter this code to complete your registration."""
    else:
        body = f"""Your password reset OTP is: {otp}
        
This OTP is valid for 5 minutes."""
    
    msg = Message(
        subject,
        recipients=[user.email],
        sender=app.config['MAIL_DEFAULT_SENDER'],
        body=body
    )
    mail.send(msg)


def get_location_from_ip(ip_address):
    """Get structured location data from IP address"""
    try:
        if ip_address == '127.0.0.1':
            return {
                'status': 'success',
                'city': 'Localhost',
                'region': 'Development',
                'country': 'Local Network',
                'postal_code': '00000'
            }

        response = requests.get(
            f'http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query')
        data = response.json()

        if data['status'] == 'success':
            return {
                'status': 'success',
                'city': data.get('city', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'postal_code': data.get('zip', ''),
                'latitude': data.get('lat'),
                'longitude': data.get('lon'),
                'isp': data.get('isp', 'Unknown ISP'),
                'ip': data.get('query', ip_address)
            }

        return {
            'status': 'error',
            'message': data.get('message', 'Unknown error')
        }

    except Exception as e:
        app.logger.error(f"IP geolocation error: {str(e)}")
        return {
            'status': 'error',
            'message': 'Service unavailable'
        }


def get_client_info(request):
    """Extract client information from request"""
    user_agent = parse(request.user_agent.string)
    ip = request.remote_addr

    location_data = get_location_from_ip(ip)

    # Format location string
    location_parts = []
    if location_data.get('postal_code'):
        location_parts.append(location_data['postal_code'])
    if location_data.get('city'):
        location_parts.append(location_data['city'])
    if location_data.get('region'):
        location_parts.append(location_data['region'])
    if location_data.get('country'):
        location_parts.append(location_data['country'])

    location_str = ", ".join(location_parts) if location_parts else "Unknown location"

    return {
        'ip': ip,
        'browser': user_agent.browser.family,
        'device': user_agent.device.family if user_agent.device.family != "Other" else "Desktop",
        'platform': user_agent.os.family,
        'location': location_str,
        'postal_code': location_data.get('postal_code'),
        'city': location_data.get('city'),
        'region': location_data.get('region'),
        'country': location_data.get('country'),
        'latitude': location_data.get('latitude'),
        'longitude': location_data.get('longitude'),
        'isp': location_data.get('isp')
    }

# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login_activities')
@login_required
def login_activities():
    return render_template('auth/login_activities.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if unverified user exists
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and not user.email_verified:
            # Resend OTP to existing unverified user
            user.username = form.username.data
            user.password_hash = generate_password_hash(form.password.data)
        else:
            # Create new user
            user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=generate_password_hash(form.password.data)
            )
            db.session.add(user)
        
        # Send OTP
        send_otp_email(user, 'registration')
        session['reg_email'] = user.email
        flash('OTP sent to your email. Please verify to complete registration.', 'info')
        return redirect(url_for('verify_registration'))
    
    return render_template('auth/register.html', form=form)

@app.route('/verify_registration', methods=['GET', 'POST'])
def verify_registration():
    if 'reg_email' not in session:
        return redirect(url_for('register'))
    
    user = User.query.filter_by(email=session['reg_email']).first()
    if not user:
        flash('Registration session expired. Please register again.', 'danger')
        return redirect(url_for('register'))
    
    form = VerifyRegistrationForm()
    if form.validate_on_submit():
        if user.otp == form.otp.data:
            if user.is_otp_expired():
                flash('OTP has expired. Please register again.', 'danger')
                return redirect(url_for('register'))
            
            # Activate user
            user.is_active = True
            user.email_verified = True
            user.otp = None
            db.session.commit()
            
            # Clean up session
            session.pop('reg_email', None)
            
            # Log in the user
            login_user(user)
            flash('Registration successful! Welcome!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    
    return render_template('auth/verify_registration.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # Get client information before any returns
        client_info = get_client_info(request)
        login_activity = LoginActivity(
            user_id=user.id if user else None,
            ip_address=client_info['ip'],
            browser=client_info['browser'],
            device=client_info['device'],
            location=client_info['location'],
            platform=client_info['platform'],
            postal_code=client_info['postal_code'],
            city=client_info['city'],
            region=client_info['region'],
            country=client_info['country'],
            latitude=client_info.get('latitude'),
            longitude=client_info.get('longitude'),
            isp=client_info.get('isp'),
            success=False
        )

        if user and user.is_locked():
            remaining_time = (user.locked_until - datetime.utcnow()).seconds // 60
            login_activity.status = "Account locked"
            db.session.add(login_activity)
            db.session.commit()

            flash(f'Account locked. Try again in {remaining_time} minutes.', 'danger')
            return redirect(url_for('login'))

        if user and user.check_password(form.password.data):
            if not user.email_verified:
                login_activity.status = "Email not verified"
                db.session.add(login_activity)
                db.session.commit()

                flash('Please verify your email before logging in.', 'warning')
                send_otp_email(user, 'registration')
                session['reg_email'] = user.email
                return redirect(url_for('verify_registration'))

            # Successful login
            login_activity.user_id = user.id
            login_activity.success = True
            login_activity.status = "Success"
            db.session.add(login_activity)

            login_user(user, remember=form.remember.data)
            user.reset_login_attempts()
            user.last_login = datetime.utcnow()

            # Keep only last 3 activities
            activities = LoginActivity.query.filter_by(user_id=user.id)\
                          .order_by(LoginActivity.login_time.desc())\
                          .offset(3).all()
            for activity in activities:
                db.session.delete(activity)

            db.session.commit()

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            # Failed login
            if user:
                user.increment_login_attempts()
                remaining_attempts = app.config['MAX_LOGIN_ATTEMPTS'] - user.login_attempts

                if remaining_attempts > 0:
                    login_activity.status = f"Failed attempt ({remaining_attempts} remaining)"
                    flash(f'Invalid credentials. {remaining_attempts} attempts remaining.', 'danger')
                else:
                    login_activity.status = "Account locked - too many attempts"
                    flash(f'Account locked for {app.config["LOGIN_LOCKOUT_MINUTES"]} minutes due to too many failed attempts.', 'danger')
            else:
                login_activity.status = "Invalid email"
                flash('Login unsuccessful. Please check email and password.', 'danger')

            db.session.add(login_activity)
            db.session.commit()

    return render_template('auth/login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_otp_email(user, 'password_reset')
            session['reset_email'] = user.email
            flash('OTP sent to your email. Please verify to reset password.', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('No account found with that email address.', 'warning')
    
    return render_template('auth/forgot_password.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=session['reset_email']).first()
    if not user:
        flash('Invalid session. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))
    
    form = VerifyOTPForm()
    if form.validate_on_submit():
        if user.otp == form.otp.data:
            if user.is_otp_expired():
                flash('OTP has expired. Please request a new one.', 'danger')
                return redirect(url_for('forgot_password'))
            
            session['otp_verified'] = True
            flash('OTP verified. Please set your new password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    
    return render_template('auth/verify_otp.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session or not session.get('otp_verified'):
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=session['reset_email']).first()
    if not user:
        flash('Invalid session. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.reset_login_attempts()
        user.otp = None
        db.session.commit()
        
        # Clean up session
        session.pop('reset_email', None)
        session.pop('otp_verified', None)
        
        flash('Your password has been updated! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/reset_password.html', form=form)

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    if 'reg_email' in session:  # Registration OTP
        user = User.query.filter_by(email=session['reg_email']).first()
        if user:
            send_otp_email(user, 'registration')
            flash('New OTP sent to your email.', 'info')
        return redirect(url_for('verify_registration'))
    elif 'reset_email' in session:  # Password reset OTP
        user = User.query.filter_by(email=session['reset_email']).first()
        if user:
            send_otp_email(user, 'password_reset')
            flash('New OTP sent to your email.', 'info')
        return redirect(url_for('verify_otp'))
    else:
        return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Create tables


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)