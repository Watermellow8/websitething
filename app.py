from flask import Flask, render_template, request, jsonify
from waitress import serve
from root import solve_roots
from flask_httpauth import HTTPBasicAuth
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import os

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    integrations=[FlaskIntegration()],
    traces_sample_rate=1.0,
    environment="production"
)

app = Flask(__name__)
auth = HTTPBasicAuth()

# Hardcoded users (
users = {
    "admin": {"password": "securepassword", "role": "admin"},
    "user": {"password": "userpassword", "role": "guest"}
}

from flask import g 

@auth.verify_password
def verify_password(username, password):
    user = users.get(username)
    if user and user['password'] == password:
        g.current_user = username
        g.current_role = user['role']
        return username
    return None

@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html")


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


@app.route('/unauthorized')
def unauthorized():
    return "Unauthorized", 401

@app.route('/debug-sentry')
@auth.login_required
def trigger_error():
    if g.get('current_role') != 'admin':
        return jsonify({'error': 'Forbidden: Admins only'}), 403
    1 / 0
    return "<p>Hello, World!</p>"

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)
