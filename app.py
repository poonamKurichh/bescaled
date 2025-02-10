from flask import Flask, render_template, redirect, url_for, current_app, request, flash
from flask_login import LoginManager, login_required, current_user
from models import db, User
from flask_jwt_extended import JWTManager
from itsdangerous import URLSafeTimedSerializer
from config import CurrentConfig
from flask_mail import Mail, Message
from routes import register_blueprints  # Import blueprint registration
from flask_migrate import Migrate
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.config.from_object(CurrentConfig)


CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})


jwt = JWTManager(app)

db.init_app(app)

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "user_routes.admin_login"  # Redirect unauthorized users to login
login_manager.session_protection = "strong"  # Ensure session security

mail = Mail(app)  # ✅ Initialize Flask-Mail

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Flask-Login User Loader
@login_manager.user_loader
def load_user(user_id):
    with current_app.app_context():
        return db.session.get(User, int(user_id))  # Corrected for SQLAlchemy 2.0

# Register blueprints
# Register all blueprints in one place
register_blueprints(app)


# Admin-only route
@app.context_processor
def inject_user():
    return {'user': current_user}

@app.route("/")
def home():
    # Redirect based on user login status
    if current_user.is_authenticated:
      return redirect(url_for('user_routes.admin_dashboard'))
    return redirect(url_for('user_routes.admin_login'))
    #return render_template('admin_login.html')

def send_email_fallback(to_email, subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = Config.MAIL_USERNAME
    msg["To"] = to_email

    try:
        with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
            server.starttls()
            server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
            server.sendmail(Config.MAIL_USERNAME, [to_email], msg.as_string())
        print("✅ Email sent successfully using smtplib!")
    except Exception as e:
        print("❌ Error sending email:", e)

# Utility function to generate a reset token
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    return serializer.dumps(email, salt="password-reset-salt")

# Utility function to verify the reset token
def verify_reset_token(token, expiration=3600):  # 1-hour expiration
    serializer = URLSafeTimedSerializer(Config.SECRET_KEY)
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=expiration)
        return email
    finally:
        return None

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Render the Forgot Password page and handle form submission."""
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if the email exists in the database
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate password reset token
            token = generate_reset_token(email)

            # Create reset link
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send email with reset link( for google smtp)
            subject = "Password Reset Request"
            body = f"Hello, click the link below to reset your password:\n{reset_url}\nThis link expires in 1 hour."
            msg = Message(subject=subject, recipients=[email], body=body)
            print("Attempting to send email...")
            print(f"Mail Sender: {Config.MAIL_USERNAME}")  # Debugging
            print(f"Mail Recipients: {[email]}")
            print(f"Mail Body: {body}")
            #mail.send(msg) #for gmail smtp
            send_email_fallback(email, subject, body)

            flash("Password reset instructions have been sent to your email.", "info")
        else:
            flash("No account found with this email address.", "danger")

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password route."""
    email = verify_reset_token(token)
    if not email:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(password)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('user_routes.admin_login'))

    return render_template('reset_password.html', token=token)

# Create tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
