import matplotlib
matplotlib.use('Agg')  # Safe for macOS/server
import numpy as np
import matplotlib.pyplot as plt
import mpld3


def solve_roots(expr, search_range=(-10, 10), num_starts=20, tolerance=1e-10, max_iter=200):
    h = expr
    expr = expr.replace('^', '**')
    
    def extract_variable(s):
        for c in s:
            if c.isalpha():
                return c
        return None

    var = extract_variable(expr)
    if var is None:
        return {"success": False}

    func_str = f"({expr})"

    def f(val):
        return eval(func_str, {"__builtins__": None, "np": np}, {var: val})

    def derivative(x, h=1e-8):
        return (f(x + h) - f(x - h)) / (2 * h)

    def newton_raphson(x):
        for _ in range(max_iter):
            try:
                y = f(x)
                if abs(y) < tolerance:
                    return x
                dy = derivative(x)
                if abs(dy) < 1e-15:
                    return None
                x_new = x - y / dy
                if abs(x_new - x) < tolerance:
                    return x_new
                x = x_new
            except:
                return None
        return None

    starts = np.linspace(*search_range, num_starts)
    raw_roots = []
    for s in starts:
        r = newton_raphson(s)
        if r is not None and abs(f(r)) < tolerance:
            raw_roots.append(r)
    
    # Normalize small values to 0.0 BEFORE deduplication (much larger threshold to catch numerical noise)
    normalized_roots = [0.0 if abs(r) < 1e-5 else r for r in raw_roots]
    
    # Deduplicate roots with appropriate tolerance
    deduped_roots = []
    for r in normalized_roots:
        if not any(abs(r - existing) < 1e-4 for existing in deduped_roots):
            deduped_roots.append(r)
    
    # Round and sort roots
    roots = sorted(float(round(r, 8)) for r in deduped_roots)

    try:
        x_vals = np.linspace(search_range[0], search_range[1], 1000)
        f_vec = np.vectorize(f)
        y_vals = f_vec(x_vals)

        fig, ax = plt.subplots()
        ax.plot(x_vals, y_vals, label=expr)
        for r in roots:
            ax.plot(r, f(r), 'ro')
            ax.annotate(f'{r:.4f}', (r, f(r)))
        ax.set_title("Function and Roots")
        ax.set_xlabel(var)
        ax.set_ylabel(f'f({var})')
        ax.legend()
        html = mpld3.fig_to_html(fig)
        plt.close(fig)
        return {
            "success": True,
            "roots": roots,
            "expression": h,
            "graph_html": html
        }
    except Exception:
        return {"success": False}

