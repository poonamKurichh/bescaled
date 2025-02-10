from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from models import db, User, UserRoles
import uuid, os  # For generating unique file names

user_routes = Blueprint('user_routes', __name__)
mail = Mail(current_app)  # Initialize Flask-Mail

# ============================
# Admin Panel Routes
# ============================


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'static/upload'
current_app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    """Check if file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@user_routes.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login route."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        print(f"Email: {email}, Password: {password}")  # Debugging
        user = User.query.filter_by(email=email).first()
        # Debugging: Print user details
        print(f"Attempting login for: {email}")
        print(f"User found: {user}")

        if user:
            print(f"Stored Role: {user.role}, Entered Password: {password}")
            print(f"Password Matches: {user.check_password(password)}")
            print(f"Role Check: {user.role in ['admin', 'manager']}")

        if user and user.check_password(password) and user.role in ['admin', 'manager']:
            login_user(user, remember=True)  # Ensure session persists

            print(f"Logged in User: {current_user}")  # Debugging
            print(f"Is Authenticated: {current_user.is_authenticated}")  # Debugging

            flash("Logged in successfully!", "success")
            return redirect(url_for('user_routes.admin_dashboard'))

        flash("Invalid credentials or insufficient permissions.", "danger")
        return redirect(url_for('user_routes.admin_login'))

    return render_template('admin_login.html')  # Render login form





"""
@user_routes.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    #Render the Forgot Password page and handle form submission.
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if the email exists in the database
        user = User.query.filter_by(email=email).first()
        if user:
            # Here, you can implement the logic for sending a password reset email

            flash("Password reset instructions have been sent to your email.", "info")
        else:
            flash("No account found with this email address.", "danger")

        return redirect(url_for('user_routes.forgot_password'))

    # Render the Forgot Password page for GET requests
    return render_template('forgot_password.html')
"""


@user_routes.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    """Admin registration route for creating new users."""
    if request.method == 'POST':
        print('Admin registration form data:', request.form)

        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        company = request.form.get('company')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')  # Get role from form input

        print(f"New User: {firstname} {lastname}, Email: {email}, Role: {role}")

        # Validate if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        print("Existing User:", existing_user)

        if existing_user:
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for('user_routes.admin_login'))

        # Validate role input
        if role.lower() not in ['admin', 'manager']:
            flash("Invalid role. Please select 'admin' or 'manager'.", "danger")
            return redirect(url_for('user_routes.admin_register'))

        # Validate password
        if not password:
            flash("Password is required!", "danger")
            return redirect(url_for('user_routes.admin_register'))

        # Create a new user
        new_user = User(
            firstname=firstname,
            lastname=lastname,
            email=email,
            company=company,  # Add company information
            role=role,  # Save the role from form input
            contact_no=''  # Optional, can be updated later
        )
        new_user.set_password(password)

        # Save to database
        try:
            db.session.add(new_user)
            db.session.commit()
            print(f"New User: {firstname} {lastname}, Email: {email}, Role: {role}")
            flash(f"{role.capitalize()} account created successfully! Please log in.", "success")
            return redirect(url_for('user_routes.admin_login'))
        except Exception as e:
            db.session.rollback()
            import traceback
            print("Database Error:", e)
            print(traceback.format_exc())  # Prints full error traceback
            flash("An error occurred while saving to the database. Please try again.", "danger")
            return redirect(url_for('user_routes.admin_register'))

    # Fetch roles from UserRoles table
    roles = UserRoles.query.all()
    return render_template('sign_up.html', roles=roles)


@user_routes.route('/admin_profile', methods=['GET', 'POST'])
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
                file_path = os.path.join(current_app.config[UPLOAD_FOLDER], unique_filename)
                file.save(file_path)
                user.profile_image = unique_filename  # Save filename in DB

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('user_routes.admin_profile'))

    return render_template('profile.html', user=user)


@user_routes.route('/admin_change_password', methods=['GET', 'POST'])
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

    return render_template('profile.html')


@user_routes.route('/admin/logout', methods=['POST'])
@login_required
def admin_logout():
    """Admin logout route."""
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('user_routes.admin_login'))


@user_routes.route('/admin/dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    """Admin dashboard route."""
    if current_user.role not in ['admin', 'manager']:
        flash("Access denied.", "danger")
        return redirect(url_for('user_routes.admin_login'))

    return render_template('index.html', user=current_user)


# ============================
# React API Routes
# ============================

@user_routes.route('api/users/login', methods=['POST'])
def login():
    """React frontend login: Returns a JWT."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Authenticate user
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        # Create a JWT with user details
        access_token = create_access_token(identity={"id": user.id, "role": user.role})
        return jsonify({"access_token": access_token, "firstname": user.firstname, "email": user.email}), 200

    return jsonify({"error": "Invalid credentials"}), 401


@user_routes.route('api/users/protected', methods=['GET'])
@jwt_required()
def protected():
    """Protected API route example."""
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello, {current_user['id']}!"}), 200


@user_routes.route('api/users/list_users', methods=['GET'])
def get_users():
    """List all users."""
    users = User.query.all()
    return jsonify([{"id": u.id, "name": u.firstname, "email": u.email} for u in users])


@user_routes.route('api/users/get_one_user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get a specific user by ID."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": user.id, "name": user.firstname, "email": user.email})


@user_routes.route('api/users/create_user', methods=['POST'])
def create_user():
    """Create a new user for React frontend."""
    data = request.get_json()

    # Validate required fields
    required_fields = ['firstname', 'lastname', 'email', 'contact_no', 'password']
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400

    # Validate role
    role = data.get('role', 'guest')
    if role not in ['admin', 'manager', 'guest']:
        return jsonify({"error": "Invalid role provided"}), 400

    # Create the new user
    new_user = User(
        firstname=data['firstname'],
        lastname=data['lastname'],
        email=data['email'],
        contact_no=data['contact_no'],
        address=data.get('address'),
        city=data.get('city'),
        country=data.get('country'),
        pincode=data.get('pincode'),
        role=role,
        business_area=data.get('business_area', 'Information technology'),
        ERP=data.get('ERP', 'SAP'),
        other_ques_comments=data.get('other_ques_comments')
    )
    new_user.set_password(data['password'])

    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully", "id": new_user.id}), 201


@user_routes.route('api/users/update_user/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Update an existing user."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    user.firstname = data.get('firstname', user.firstname)
    user.email = data.get('email', user.email)
    db.session.commit()

    return jsonify({"id": user.id, "firstname": user.firstname, "email": user.email})


@user_routes.route('api/users/del_user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete a user."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"})
