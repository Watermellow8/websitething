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

# --- Models ---
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'))
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    roles = db.relationship('Role', secondary=user_roles, backref='users')

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary=role_permissions, backref='roles')

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
    for role in user.roles:
        for perm in role.permissions:
            if perm.name == permission_name:
                return True
    return False

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
def register_user():
    if not user_has_permission('create_user'):
        abort(403)

    username = request.form.get('username')
    password = request.form.get('password')
    role_names = request.form.getlist('roles')

    if not username or not password or not role_names:
        return "Missing username, password, or roles", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    roles = Role.query.filter(Role.name.in_(role_names)).all()
    if not roles:
        return "Invalid roles", 400

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        roles=roles
    )
    db.session.add(new_user)
    db.session.commit()
    return f"User '{username}' registered successfully!", 201

@app.route('/create-admin', methods=['POST'])
@auth.login_required
@permission_required('create_ad')
def create_admin():
    username = request.form.get('username') or request.json.get('username')
    password = request.form.get('password') or request.json.get('password')

    if not username or not password:
        return "Missing username or password", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        return "Admin role not found", 500

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        roles=[admin_role]
    )
    db.session.add(new_user)
    db.session.commit()
    return f"Admin user '{username}' created successfully!", 201

@app.route('/unauthorized')
def unauthorized():
    return "Unauthorized", 401

# --- CLI Command to initialize DB ---
@app.cli.command('init-auth')
@app.cli.command('init-auth')
def init_auth():
    db.create_all()

    # Create permissions
    perms = ['solve_function', 'trigger_error', 'create_user', 'create_ad']
    for pname in perms:
        if not Permission.query.filter_by(name=pname).first():
            db.session.add(Permission(name=pname))
    db.session.commit()

    # Fetch permissions from DB
    solve_perm = Permission.query.filter_by(name='solve_function').first()
    error_perm = Permission.query.filter_by(name='trigger_error').first()
    create_perm = Permission.query.filter_by(name='create_user').first()
    create_ad = Permission.query.filter_by(name='create_ad').first()

    # Create roles if not exist
    if not Role.query.filter_by(name='owner').first():
        owner_role = Role(name='owner', permissions=[solve_perm, error_perm, create_ad])
        db.session.add(owner_role)

    if not Role.query.filter_by(name='admin').first():
        admin_role = Role(name='admin', permissions=[solve_perm, error_perm, create_perm])
        db.session.add(admin_role)

    if not Role.query.filter_by(name='guest').first():
        guest_role = Role(name='guest', permissions=[solve_perm])
        db.session.add(guest_role)

    db.session.commit()  # Commit roles

    # Retrieve roles again from DB (safe and committed)
    owner_role = Role.query.filter_by(name='owner').first()
    admin_role = Role.query.filter_by(name='admin').first()
    guest_role = Role.query.filter_by(name='guest').first()

    # Create users if they don't exist
    if not User.query.filter_by(username='owned').first():
        owner_user = User(
            username='owned',
            password_hash=generate_password_hash('trollhd'),
            roles=[owner_role]
        )
        db.session.add(owner_user)
        db.session.commit()
        print("Owner user created.")
    else:
        print("Owner user already exists.")

    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            password_hash=generate_password_hash('securepassword'),
            roles=[admin_role]
        )
        db.session.add(admin_user)
        print("Admin user created.")
    else:
        print("Admin user already exists.")

    if not User.query.filter_by(username='guest').first():
        guest_user = User(
            username='guest',
            password_hash=generate_password_hash('guestpassword'),
            roles=[guest_role]
        )
        db.session.add(guest_user)
        print("Guest user created.")
    else:
        print("Guest user already exists.")

    db.session.commit()

# --- Start server ---
if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)
