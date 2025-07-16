from flask import Flask, render_template, request, jsonify, g, abort
from waitress import serve
from root import solve_roots
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import os
from functools import wraps

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    integrations=[FlaskIntegration()],
    traces_sample_rate=1.0,
    environment="production"
)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'guest'

@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        g.current_user = user.username
        g.current_role = user.role
        return True
    return False

### Role-based Authorization Decorator ###
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if g.get('current_role') != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
@app.route('/index')
@auth.login_required
def index():
    return render_template("index.html", role=g.current_role, username=g.current_user)

@app.route('/solve')
@auth.login_required
def solve():
    expr = request.args.get('expression', '').strip()

    if not expr:
        return render_template("function-not-found.html")

    result = solve_roots(expr)

    if not result['success']:
        return render_template("function-not-found.html")

    return render_template(
        "result.html",
        expression=result["expression"],
        roots=result["roots"],
        graph=result["graph_html"],
        role=g.current_role
    )

@app.route('/debug-sentry')
@auth.login_required
@role_required('admin')
def trigger_error():
    1 / 0  # Intentional crash for Sentry
    return "<p>Hello, World!</p>"

@app.route('/unauthorized')
def unauthorized():
    return "Unauthorized", 401

@app.cli.command('create-users')
def create_users():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('securepassword'),
            role='admin'
        )
        guest = User(
            username='user',
            password_hash=generate_password_hash('userpassword'),
            role='guest'
        )
        db.session.add(admin)
        db.session.add(guest)
        db.session.commit()
        print("Admin and guest users created.")
    else:
        print("Users already exist.")

@app.route('/register', methods=['POST'])
@auth.login_required
def register_guest():
    if g.current_role not in ['admin', 'guest']:
        abort(403)

    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return "Missing username or password", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    guest = User(
        username=username,
        password_hash=generate_password_hash(password),
        role='guest'
    )
    db.session.add(guest)
    db.session.commit()
    return f"Guest user '{username}' registered successfully!"

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)

