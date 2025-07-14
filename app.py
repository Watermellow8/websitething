from flask import Flask, render_template, request
from waitress import serve
from root import solve_roots
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