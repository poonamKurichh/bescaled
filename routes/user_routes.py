from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash, current_app, abort
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Message

from config import CurrentConfig
from models import db
from models.user import User, UserRoles
import os
import uuid



# Initialize Blueprint
user_routes = Blueprint('user_routes', __name__)

# Configurations for file uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/upload'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)



# ============================
# Helper Functions
# ============================

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_role(role, allowed_roles=['admin', 'manager']):
    """Check if the role is valid."""
    return role.lower() in allowed_roles


def role_required(allowed_roles):
    """Decorator to enforce role-based access control."""

    def decorator(func):
        from functools import wraps
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in allowed_roles:
                flash("Access denied: Insufficient permissions.", "danger")
                return redirect(url_for('user_routes.admin_login'))
            return func(*args, **kwargs)

        return wrapper

    return decorator


# ============================
# Admin Panel Routes
# ============================

@user_routes.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login route."""
    if request.method == 'POST':
        email = request.form.get('email')
        email = email.strip()
        password = request.form.get('password')

        print(f"Email: {email}, Password: {password}")  # Debugging

        user = User.query.filter_by(email=email).first()
        # Debugging: Print user details
        print(f"Attempting login for: {email}")
        print(f"User found: {user}")

        if user and user.check_password(password) and user.role in ['admin', 'manager']:
            login_user(user)

            flash("Logged in successfully!", "success")
            current_app.logger.info(f"Admin {email} logged in.")
            return redirect(url_for('user_routes.admin_dashboard'))

        flash("Invalid credentials or insufficient permissions.", "danger")
        current_app.logger.warning(f"Failed login attempt for: {email}")
        return redirect(url_for('user_routes.admin_login'))

    return render_template('pages/admin_login.html')


@user_routes.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    """Admin registration route for creating new users."""
    if request.method == 'POST':
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        if not validate_role(role):
            flash("Invalid role: Must be admin or manager.", "danger")
            return redirect(url_for('user_routes.admin_register'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for('user_routes.admin_register'))

        new_user = User(
            firstname=firstname, lastname=lastname, email=email, role=role
        )
        new_user.set_password(password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f"{role.capitalize()} account created successfully! Please log in.", "success")
            current_app.logger.info(f"New {role} registered: {email}")
            return redirect(url_for('user_routes.admin_login'))
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating user: {e}")
            flash("An error occurred during registration. Please try again.", "danger")
            return redirect(url_for('user_routes.admin_register'))

    roles = UserRoles.query.all()  # Fetch roles dynamically if needed
    print('user roles:', roles)
    return render_template('pages/sign_up.html', roles=roles)

#========================================
# Forgot & Reset Password APIs for admin
# =======================================

@user_routes.route('/forgot_password', methods=['GET','POST'])
def forgot_password():
    """
    Admin forgot password API to send a reset password email.
    Receives: { "email": "admin@example.com" }
    """
    if request.method == "POST":
        data = request.get_json()
        email = data.get("email")

        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Check if the email exists in the database
        user = User.query.filter_by(email=email).first()
        if not user or user.role not in ['admin', 'manager']:
            return jsonify({"error": "Invalid email or account not found."}), 404

        # Create a unique token for the user
        token = serializer.dumps(email, salt='password-reset-salt')
        reset_url = url_for('user_routes.reset_password', token=token, _external=True)

        # Send the reset email
        try:
            msg = Message(subject="Reset Your Password",
                          sender=current_app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[email],
                          body=f"Click the link to reset your password: {reset_url}")
            mail.send(msg)
            current_app.logger.info(f"Password reset email sent to {email}")
            return jsonify({"message": "Password reset email sent successfully."}), 200
        except Exception as e:
            current_app.logger.error(f"Error sending reset email to {email}: {e}")
            return jsonify({"error": "Failed to send the reset email. Please try again later."}), 500
    return render_template('pages/forgot_password.html')

@user_routes.route('/reset_password/<token>', methods=['GET','POST'])
def reset_password(token):
    """
    Admin reset password API to update the password.
    Receives: { "new_password": "newpassword", "confirm_password": "newpassword" }
    """
    if request.method == "POST":
        data = request.get_json()
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if not new_password or not confirm_password:
            return jsonify({"error": "Both new_password and confirm_password are required"}), 400

        if new_password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        try:
            # Validate the token
            email = serializer.loads(token, salt="password-reset-salt", max_age=3600)  # 1 hour expiration
        except SignatureExpired:
            return jsonify({"error": "The reset password link has expired. Please try again."}), 400
        except BadSignature:
            return jsonify({"error": "Invalid reset token."}), 400

        # Find the user by email
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "User not found."}), 404

        # Update the password
        try:
            user.set_password(new_password)
            db.session.commit()
            current_app.logger.info(f"Password reset successfully for {email}")
            return jsonify({"message": "Password reset successfully."}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Failed to reset password for {email}: {e}")
            return jsonify({"error": "Failed to reset password. Please try again later."}), 500
    return render_template('pages/reset_password.html')

@user_routes.route('/admin/dashboard', methods=['GET'])
@login_required
@role_required(['admin', 'manager'])
def admin_dashboard():
    """Admin dashboard route."""
    return render_template('pages/index.html', user=current_user)


@user_routes.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    """Admin profile route."""
    user = User.query.get(current_user.id)  # Fetch user from DB
    print("Current User:", user)  # Debugging
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('user_routes.admin_profile'))

    if request.method == 'POST':
        print('Form data:', request.form.to_dict())  # Debugging


        user.firstname = request.form.get('firstname', '').strip()
        user.lastname = request.form.get('lastname', '').strip()
        user.email = request.form.get('email', '').strip()
        user.contact_no = request.form.get('phone', '').strip()
        user.address = request.form.get('address', '').strip()
        user.city = request.form.get('city', '').strip()
        user.country = request.form.get('country', '').strip()
        user.pincode = request.form.get('pincode', '').strip()
        user.company = request.form.get('company', '').strip()
        user.job = request.form.get('job', '').strip()  # Preserve spaces
        user.about = request.form.get('about', '').strip()
        user.facebook_profile = request.form.get('facebook', '').strip()
        user.twitter_profile = request.form.get('twitter', '').strip()
        user.linkedin_profile = request.form.get('linkedin', '').strip()
        user.instagram_profile = request.form.get('instagram', '').strip()

        # Handle profile image upload
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"  # Generate a unique name
                file_path = os.path.join(CurrentConfig.UPLOAD_FOLDER, unique_filename)
                #file_path = os.path.join(current_app.Config[UPLOAD_FOLDER] , unique_filename)
                file.save(file_path)
                user.profile_image = unique_filename  # Save filename in DB

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('user_routes.admin_profile'))

    return render_template('pages/profile.html', user=user)

@user_routes.route('/admin/change_password', methods=['GET', 'POST'])
@login_required
def admin_change_password():
    """Admin change password route."""
    if request.method == 'POST':
        current_password = request.form.get('password')
        new_password = request.form.get('newpassword')
        renew_password = request.form.get('renewpassword')

        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('user_routes.admin_change_password'))

        if new_password != renew_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('user_routes.admin_change_password'))

        current_user.set_password(new_password)
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('user_routes.admin_dashboard'))

    return render_template('pages/profile.html')

@user_routes.route('/admin/logout', methods=['POST'])
@login_required
def admin_logout():
    """Admin logout route."""
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('user_routes.admin_login'))


# ============================
# React API Routes
# ============================

@user_routes.route('/api/users/login', methods=['POST'])
def api_login():
    """React frontend login: Returns a JWT."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity={"id": user.id, "role": user.role})
        current_app.logger.info(f"User {email} logged in via API.")
        return jsonify({"access_token": access_token, "id": user.id, "role": user.role}), 200

    current_app.logger.warning(f"Failed API login attempt for: {email}")
    return jsonify({"error": "Invalid credentials"}), 401


@user_routes.route('/api/users/create', methods=['POST'])
def create_user():
    """Create a new user for React frontend."""
    data = request.get_json()
    required_fields = ['firstname', 'lastname', 'email', 'password', 'role']
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400

    if not validate_role(data['role'], allowed_roles=['admin', 'manager', 'guest']):
        return jsonify({"error": "Invalid role"}), 400

    new_user = User(
        firstname=data['firstname'],
        lastname=data['lastname'],
        email=data['email'],
        role=data['role']
    )
    new_user.set_password(data['password'])

    try:
        db.session.add(new_user)
        db.session.commit()
        current_app.logger.info(f"New user created via API: {data['email']}")
        return jsonify({"message": "User created successfully", "id": new_user.id}), 201
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating API user: {e}")
        return jsonify({"error": "Failed to create user"}), 500

@user_routes.route('/api/users/forgot_password', methods=['POST'])
def react_forgot_password():
    """
    React forgot password API to send a reset password email.
    Receives: { "email": "user@example.com" }
    """
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Invalid email or user not found."}), 404

    # Create a token
    token = serializer.dumps(email, salt='password-reset-salt')
    reset_url = url_for('user_routes.react_reset_password', token=token, _external=True)

    # Send reset email
    try:
        msg = Message(subject="Reset Your Password",
                      sender=current_app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[email],
                      body=f"Click this link to reset your password: {reset_url}")
        mail.send(msg)
        current_app.logger.info(f"Password reset email sent to {email}")
        return jsonify({"message": "Password reset email sent successfully."}), 200
    except Exception as e:
        current_app.logger.error(f"Error sending reset email to {email}: {e}")
        return jsonify({"error": "Failed to send the reset email. Please try again later."}), 500


@user_routes.route('/api/users/reset_password/<token>', methods=['POST'])
def react_reset_password(token):
    """
    React reset password API to update password.
    Receives: { "new_password": "newpassword", "confirm_password": "newpassword" }
    """
    data = request.get_json()
    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    if not new_password or not confirm_password:
        return jsonify({"error": "Both new_password and confirm_password are required"}), 400

    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)  # 1 hour expiration
    except SignatureExpired:
        return jsonify({"error": "The reset password link has expired."}), 400
    except BadSignature:
        return jsonify({"error": "Invalid reset token."}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    try:
        user.set_password(new_password)
        db.session.commit()
        current_app.logger.info(f"User password reset successfully: {email}")
        return jsonify({"message": "Password reset successful."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to reset password for {email}: {e}")
        return jsonify({"error": "Password reset failed. Try again."}), 500


# ============================
# React APIs: Manage Users
# ============================

@user_routes.route('/api/users/delete/<int:user_id>', methods=['DELETE'])
@jwt_required()
def react_delete_user(user_id):
    """
    React API to delete a user by ID (Admin only).
    """
    current_user_identity = get_jwt_identity()
    if current_user_identity['role'] != 'admin':
        return jsonify({"error": "Access denied. Admin privilege required."}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        current_app.logger.info(f"User deleted successfully: {user.email}")
        return jsonify({"message": "User deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to delete user {user.email}: {e}")
        return jsonify({"error": "Failed to delete user. Try again."}), 500


@user_routes.route('/api/users/edit/<int:user_id>', methods=['PUT'])
@jwt_required()
def react_edit_user(user_id):
    """
    React API to edit an existing user by ID.
    Expects: {
        "firstname": "NewName",
        "lastname": "NewLast",
        "role": "manager"
    }
    """
    data = request.get_json()
    current_user_identity = get_jwt_identity()
    if current_user_identity['role'] != 'admin':
        return jsonify({"error": "Access denied. Admin privilege required."}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found."}), 404

    # Update user fields
    firstname = data.get("firstname", user.firstname)
    lastname = data.get("lastname", user.lastname)
    role = data.get("role", user.role)

    if role and not validate_role(role):
        return jsonify({"error": "Invalid role."}), 400

    user.firstname = firstname
    user.lastname = lastname
    user.role = role

    try:
        db.session.commit()
        current_app.logger.info(f"User updated successfully: {user.email}")
        return jsonify({"message": "User updated successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to update user {user.email}: {e}")
        return jsonify({"error": "Failed to update user. Try again."}), 500

