from flask import Flask, render_template, request, jsonify
from waitress import serve
from root import solve_roots
from flask_httpauth import HTTPBasicAuth
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import os

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),  # Pull from environment variable
    integrations=[FlaskIntegration()],
    traces_sample_rate=1.0,
    environment="production"
)

app = Flask(__name__)
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    if username in users and users[username] == password:
        return username
    return None

@auth.error_handler
def unauthorized():
    return jsonify({'error': 'Unauthorized access'}), 401


@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html")


@app.route('/solve')
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
def trigger_error():
    1 / 0  # Deliberate crash to test Sentry
    return "<p>Hello, World!</p>"


if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)

