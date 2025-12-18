from flask import Flask, render_template, request, redirect, session, url_for, make_response, current_app
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from api_key import CLIENT_ID, CLIENT_SECRET

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    # Use Google's OpenID Connect discovery document so Authlib can obtain jwks_uri
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# User model - single row table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Home route
@app.route('/')
def home():
    if "username" in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# login route
@app.route('/login', methods=['POST'])
def login():
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template("index.html", message="Invalid credentials"), 401
    

# Register route
@app.route('/register', methods=['POST'])
def register():
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:    
            return render_template("index.html", message="Username already exists"), 400
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = username
            return redirect(url_for('dashboard'))
        
    
# Dashbord route
@app.route('/dashboard')
def dashboard():
    if "username" in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('home'))

# Logout route (revoke provider token, clear session, delete cookie)
@app.route('/logout')
def logout():
    # Revoke token at provider if present
    oauth_token = session.pop('oauth_token', None)
    if oauth_token:
        access_token = None
        if isinstance(oauth_token, dict):
            access_token = oauth_token.get('access_token')
        else:
            access_token = oauth_token
        if access_token:
            try:
                requests.post(
                    'https://oauth2.googleapis.com/revoke',
                    params={'token': access_token},
                    headers={'content-type': 'application/x-www-form-urlencoded'},
                    timeout=5,
                )
            except Exception:
                app.logger.exception('Failed to revoke token')

    # Clear session and username
    session.pop('username', None)
    session.clear()

    # Remove session cookie and redirect home
    resp = make_response(redirect(url_for('home')))
    resp.delete_cookie(current_app.config.get('SESSION_COOKIE_NAME', 'session'))
    return resp




# login for google
@app.route('/login/google')
def login_google():
    try:
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        app.logger.error(f"Error during Google login: {str(e)}") 
        return "Error during Google login", 500

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    userinfo_endpoint = google.server_metadata.get('userinfo_endpoint')
    resp = google.get(userinfo_endpoint)
    user_info = resp.json()
    # You can add logic here to handle the user info, e.g., create a user in your database
    username = user_info['email']
    
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username) 
        db.session.add(user)
        db.session.commit()

    session['username'] = username
    session['oauth_token'] = token
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
