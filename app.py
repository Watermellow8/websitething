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

# Models
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
    name = db.Column(db.String(80), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary=role_permissions, backref='roles')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

# Auth
@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        g.current_user = user
        return True
    return False

# Permission check

def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = g.get('current_user')
            if not user:
                abort(403)
            for role in user.roles:
                for perm in role.permissions:
                    if perm.name == permission_name:
                        return f(*args, **kwargs)
            abort(403)
        return decorated_function
    return decorator

@app.route('/')
@app.route('/index')
@auth.login_required
def index():
    return render_template("index.html", username=g.current_user.username, role_names=[r.name for r in g.current_user.roles])

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
        role_names=[r.name for r in g.current_user.roles]
    )

@app.route('/debug-sentry')
@auth.login_required
@permission_required('trigger_error')
def trigger_error():
    1 / 0  # Intentional crash for Sentry
    return "<p>Hello, World!</p>"

@app.route('/unauthorized')
def unauthorized():
    return "Unauthorized", 401

@app.cli.command('create-users')
def create_users():
    db.create_all()

    # Create permissions
    p1 = Permission(name='trigger_error')
    db.session.add(p1)
    db.session.commit()

    # Create roles
    admin_role = Role(name='admin')
    guest_role = Role(name='guest')
    admin_role.permissions.append(p1)

    db.session.add_all([admin_role, guest_role])
    db.session.commit()

    # Create users
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('securepassword')
        )
        admin.roles.append(admin_role)

        guest = User(
            username='user',
            password_hash=generate_password_hash('userpassword')
        )
        guest.roles.append(guest_role)

        db.session.add_all([admin, guest])
        db.session.commit()
        print("Admin and guest users created.")
    else:
        print("Users already exist.")

@app.route('/register', methods=['POST'])
@auth.login_required
def register_guest():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return "Missing username or password", 400

    if User.query.filter_by(username=username).first():
        return "User already exists", 400

    user = User(
        username=username,
        password_hash=generate_password_hash(password)
    )
    guest_role = Role.query.filter_by(name='guest').first()
    if guest_role:
        user.roles.append(guest_role)
    db.session.add(user)
    db.session.commit()
    return f"Guest user '{username}' registered successfully!"

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)
