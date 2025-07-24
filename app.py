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

# --- Initialize Sentry ---
sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    integrations=[FlaskIntegration()],
    traces_sample_rate=1.0,
    environment="production"
)

# --- App and DB setup ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

# --- Association tables ---
user_permissions = db.Table('user_permissions',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'))
)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    permissions = db.relationship('Permission', secondary=user_permissions, backref='users')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# --- Auth ---
@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        g.current_user = user
        return True
    return False

def user_has_permission(permission_name):
    user = g.get('current_user')
    if not user:
        return False
    return any(p.name == permission_name for p in user.permissions)

def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not user_has_permission(permission_name):
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# --- Routes ---
@app.route('/')
@app.route('/index')
@auth.login_required
def index():
    return render_template(
        "index.html",
        username=g.current_user.username,
        can_create_users=user_has_permission('create_user'),
        can_create_admins=user_has_permission('create_ad')
    )

@app.route('/solve')
@auth.login_required
@permission_required('solve_function')
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
        graph=result["graph_html"]
    )

@app.route('/debug-sentry')
@auth.login_required
@permission_required('trigger_error')
def trigger_error():
    1 / 0
    return "This should never return."

@app.route('/register', methods=['POST'])
@auth.login_required
@permission_required('create_user')
def register_user():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return "Missing username or password", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    # Always assign solve_function and create_user
    solve = Permission.query.filter_by(name='solve_function').first()
    create_user = Permission.query.filter_by(name='create_user').first()

    if not solve or not create_user:
        return "Required permissions not found in database", 500

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        permissions=[solve, create_user]
    )
    db.session.add(new_user)
    db.session.commit()
    return f"User '{username}' registered with solve + create_user permissions!", 201

@app.route('/create-admin', methods=['POST'])
@auth.login_required
@permission_required('create_ad')
def create_admin():
    data = request.form or request.json
    username = data.get('username')
    password = data.get('password')
    perm_names = data.getlist('permissions') if request.form else data.get('permissions', [])

    if not username or not password or not perm_names:
        return "Missing username, password, or permissions", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    forbidden = {'create_ad', 'create_own'}
    if any(p in forbidden for p in perm_names):
        return "You cannot assign 'create_ad' or 'create_own' permissions", 403

    perms = Permission.query.filter(Permission.name.in_(perm_names)).all()
    if not perms or len(perms) != len(set(perm_names)):
        return "One or more permissions are invalid", 400

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        permissions=perms
    )
    db.session.add(new_user)
    db.session.commit()
    return f"Admin user '{username}' created successfully!", 201

@app.route('/create-owner', methods=['POST'])
@auth.login_required
@permission_required('create_own')
def create_owner():
    data = request.form or request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return "Missing username or password", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    # Assign only these permissions: solve, sentry debug, and create_ad
    allowed = Permission.query.filter(Permission.name.in_([
        'solve_function', 'trigger_error', 'create_ad'
    ])).all()

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        permissions=allowed
    )
    db.session.add(new_user)
    db.session.commit()
    return f"Owner user '{username}' created successfully.", 201

@app.route('/unauthorized')
def unauthorized():
    return "Unauthorized", 401

# --- CLI Command to initialize DB ---
@app.cli.command('init-auth')
def init_auth():
    db.create_all()

    # Create permissions
    perms = ['solve_function', 'trigger_error', 'create_user', 'create_ad', 'create_own']
    for pname in perms:
        if not Permission.query.filter_by(name=pname).first():
            db.session.add(Permission(name=pname))
    db.session.commit()

    # Fetch permissions
    solve = Permission.query.filter_by(name='solve_function').first()
    error = Permission.query.filter_by(name='trigger_error').first()
    create_user = Permission.query.filter_by(name='create_user').first()
    create_ad = Permission.query.filter_by(name='create_ad').first()
    create_own = Permission.query.filter_by(name='create_own').first()

    # Create users with explicit permissions
    def create_user_if_not_exists(username, password, perms):
        if User.query.filter_by(username=username).first():
            print(f"User {username} already exists.")
            return
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            permissions=perms
        )
        db.session.add(user)
        db.session.commit()
        print(f"User {username} created.")

    create_user_if_not_exists('owned', 'trollhd', [solve, error, create_own])
    create_user_if_not_exists('admin', 'securepassword', [solve, error, create_ad])
    create_user_if_not_exists('guest', 'guestpassword', [solve, create_user])

# --- Start server ---
if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)