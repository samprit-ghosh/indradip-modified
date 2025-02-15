import os
from flask import Flask, session, render_template, redirect, url_for, request, flash
import google_auth_oauthlib.flow
import google.auth.transport.requests
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from flask_sqlalchemy import SQLAlchemy

# Allow HTTP (only for local development)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure key





# Hardcoded Admin Credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Query Model
class Query(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Query {self.id} - {self.first_name} {self.last_name}>'


# Create database tables
with app.app_context():
    db.create_all()

# OAuth 2.0 Configuration
CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"]

# Ensure correct redirect URI
REDIRECT_URI = "http://localhost:5000/oauth2callback"

@app.route('/')
def index():
    user = session.get('user')
    return render_template('index.html', user=user)

@app.route('/contact')
def contact():
    user = session.get('user')
    return render_template('contact.html', user=user)

@app.route('/login')
def login():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    
    flow.redirect_uri = REDIRECT_URI
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',  # Ensures refresh token is granted
        include_granted_scopes='true',
        prompt='select_account'  # Forces Google to show "Choose Account" screen
    )

    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('state')

    if not state:
        return "Invalid state parameter", 400

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    
    flow.redirect_uri = REDIRECT_URI
    authorization_response = request.url

    try:
        flow.fetch_token(authorization_response=authorization_response)
    except Exception as e:
        return f"OAuth Error: {e}", 400

    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    # Fetch user info from Google API
    service = build('oauth2', 'v2', credentials=credentials)
    user_info = service.userinfo().get().execute()

    session['user'] = {
        'name': user_info.get('name', 'Unknown'),
        'email': user_info.get('email', 'Unknown'),
        'picture': user_info.get('picture', '')
    }

    return redirect(url_for('home'))  # Redirect to the home page

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'user' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        print("📩 Form Submitted:", request.form)  # Debugging print

        category = request.form.get('category')
        first_name = request.form.get('fname')
        last_name = request.form.get('lname')
        email = request.form.get('email')
        phone = request.form.get('phone')
        message = request.form.get('message')

        # Check if form data is received
        if not all([category, first_name, last_name, email, phone, message]):
            print("❌ Missing form fields!")  # Debugging print
            flash("All fields are required!", "danger")
            return redirect(url_for('home'))

        try:
            new_query = Query(
                category=category,
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone=phone,
                message=message
            )

            db.session.add(new_query)
            db.session.commit()
            print("✅ Data Saved Successfully!")  # Debugging print

            flash("Query submitted successfully!", "success")
        except Exception as e:
            print("⚠️ Database Error:", e)  # Debugging print
            db.session.rollback()
            flash("An error occurred while saving your query.", "danger")

        return redirect(url_for('home'))

    user = session.get('user')
    return render_template('home.html', user=user)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Admin Login Route
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True  # Set session for admin login
            return redirect(url_for('admin_dashboard'))  # ✅ Fixed incorrect redirect
        else:
            flash('Invalid credentials. Try again.', 'danger')
    user = session.get('user')
    return render_template('admin_login.html', user=user)

# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))  # ✅ Fixed incorrect redirect
    queries = Query.query.all()  # Fetch all user queries from the database
    user = session.get('user')
    return render_template('admin.html', queries=queries, user=user)


@app.route('/delete/<int:id>', methods=['POST'])
def delete_query(id):
    if not session.get('admin'):  # Ensure only admin can delete
        flash("Unauthorized access!", "danger")
        return redirect(url_for('admin_dashboard'))

    query = Query.query.get_or_404(id)  # Get the query by ID or return 404
    db.session.delete(query)  # Delete the record
    db.session.commit()  # Commit changes

    flash("Query deleted successfully!", "success")
    return redirect(url_for('admin_dashboard'))
# Admin Logout
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)  # Remove admin session
    flash("Admin logged out successfully.", "success")  # Optional flash message
    return redirect(url_for('admin_login'))  # ✅ Redirect to admin login page

if __name__ == '__main__':
    app.run(debug=True)
