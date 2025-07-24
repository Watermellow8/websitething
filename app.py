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

user_permissions = db.Table('user_permissions',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'))
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    permissions = db.relationship('Permission', secondary=user_permissions, backref='users')

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_permission(self, perm_name):
        return any(p.name == perm_name for p in self.permissions)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)

@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.verify_password(password):
        return user
    return None

def permission_required(permission):
    def decorator(f):
        def wrapper(*args, **kwargs):
            user = auth.current_user()
            if not user or not user.has_permission(permission):
                return 'Permission denied', 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return auth.login_required(wrapper)
    return decorator

@app.cli.command('init-auth')
def init_auth():
    db.drop_all()
    db.create_all()

    # Create permissions
    perm_names = ['solve_function', 'trigger_error', 'create_user', 'create_mod', 'create_admin']
    perms = [Permission(name=name) for name in perm_names]
    db.session.add_all(perms)
    db.session.commit()

    # Create owner
    owner = User(username='owner', password_hash=generate_password_hash('owner'))
    owner.permissions = perms
    db.session.add(owner)
    db.session.commit()

    print("Initialized auth with default owner.")

@app.route('/create-user', methods=['POST'])
@permission_required('create_user')
def create_user_route():
    data = request.form or request.json
    username = data.get('username')
    password = data.get('password')
    requested = set(data.get('permissions', []))

    if not username or not password:
        return "Missing username or password", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    allowed = {'solve_function', 'create_user'}
    if not requested.issubset(allowed):
        return "Permission denied for some requested permissions", 403

    perms = Permission.query.filter(Permission.name.in_(requested)).all()
    new_user = User(username=username, password_hash=generate_password_hash(password), permissions=perms)
    db.session.add(new_user)
    db.session.commit()
    return f"User '{username}' created successfully!", 201

@app.route('/create-mod', methods=['POST'])
@permission_required('create_mod')
def create_mod():
    data = request.form or request.json
    username = data.get('username')
    password = data.get('password')
    requested = set(data.get('permissions', []))

    if not username or not password or not requested:
        return "Missing required fields", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    disallowed = {'create_admin', 'create_mod'}
    if requested & disallowed:
        return "Cannot assign restricted permissions", 403

    perms = Permission.query.filter(Permission.name.in_(requested)).all()
    new_user = User(username=username, password_hash=generate_password_hash(password), permissions=perms)
    db.session.add(new_user)
    db.session.commit()
    return f"Moderator user '{username}' created successfully!", 201

@app.route('/create-admin', methods=['POST'])
@permission_required('create_admin')
def create_admin():
    data = request.form or request.json
    username = data.get('username')
    password = data.get('password')
    requested = set(data.get('permissions', []))

    if not username or not password or not requested:
        return "Missing required fields", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    perms = Permission.query.filter(Permission.name.in_(requested)).all()
    new_user = User(username=username, password_hash=generate_password_hash(password), permissions=perms)
    db.session.add(new_user)
    db.session.commit()
    return f"Admin user '{username}' created successfully!", 201

@app.route('/solve', methods=['POST'])
@permission_required('solve_function')
def solve():
    data = request.form or request.json
    expr = data.get('expr', '')
    try:
        result = solve_roots(expr)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        sentry_sdk.capture_exception(e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/trigger-error')
@permission_required('trigger_error')
def trigger_error():
    raise RuntimeError("This is a test error for Sentry!")

if __name__ == '__main__':
    app.run(debug=True)
