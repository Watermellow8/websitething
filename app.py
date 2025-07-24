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
        can_create_admins=user_has_permission('create_ad'),
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

    graph = "<div style='width:100px;height:100px;background:red;'>Test Graph</div>"
    return render_template(
        "result.html",
        expression=result["expression"],
        roots=result["roots"],
        graph=graph,
        permissions=[p.name for p in g.current_user.permissions]
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
    data = request.form or request.json
    username = data.get('username')
    password = data.get('password')
    requested = request.form.getlist('permissions') or data.get('permissions', [])

    if not username or not password:
        return "Missing username or password", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    allowed_set = {'solve_function', 'trigger_error', 'create_user', 'graph'}
    filtered = [p for p in requested if p in allowed_set]

    if not filtered:
        return "Must assign at least one valid permission", 400

    allowed = Permission.query.filter(Permission.name.in_(filtered)).all()

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        permissions=allowed
    )
    db.session.add(new_user)
    db.session.commit()
    return f"User '{username}' created with permissions: {', '.join(filtered)}", 201


@app.route('/create-admin', methods=['POST'])
@auth.login_required
@permission_required('create_ad')
def create_admin():
    data = request.form or request.json
    username = data.get('username')
    password = data.get('password')
    requested = request.form.getlist('permissions') or data.get('permissions', [])

    if not username or not password:
        return "Missing username or password", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    allowed_set = {'solve_function', 'trigger_error', 'create_ad', 'create_user', 'graph'}
    filtered = [p for p in requested if p in allowed_set]

    if not filtered:
        return "Must assign at least one valid permission", 400

    allowed = Permission.query.filter(Permission.name.in_(filtered)).all()

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        permissions=allowed
    )
    db.session.add(new_user)
    db.session.commit()
    return f"Admin user '{username}' created with permissions: {', '.join(filtered)}", 201

@app.route('/unauthorized')
def unauthorized():
    return "Unauthorized", 401

# --- CLI Command to initialize DB ---
@app.cli.command('init-auth')
def init_auth():
    db.create_all()

    # Create permissions
    perms = ['solve_function', 'trigger_error', 'create_user', 'create_ad','graph']
    for pname in perms:
        if not Permission.query.filter_by(name=pname).first():
            db.session.add(Permission(name=pname))
    db.session.commit()

    # Fetch permissions
    solve = Permission.query.filter_by(name='solve_function').first()
    error = Permission.query.filter_by(name='trigger_error').first()
    create_user = Permission.query.filter_by(name='create_user').first()
    create_ad = Permission.query.filter_by(name='create_ad').first()
    graph = Permission.query.filter_by(name='graph').first()

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

    create_user_if_not_exists('owned', 'trollhd', [solve, error, create_ad,graph])
    create_user_if_not_exists('admin', 'securepassword', [solve, error, create_user,graph])
    create_user_if_not_exists('guest', 'guestpassword', [solve,graph])

# --- Start server ---
if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)