from flask import Flask, render_template, request
from waitress import serve
from root import solve_roots

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


if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)

