"""The training engine: logistic regression by gradient descent, written by hand in NumPy.

Moved here from notebooks/01_numpy_training_loop.ipynb (build steps 2-3). It knows nothing
about Streamlit, plotting, or vulnerabilities. It takes arrays and yields numbers (SDD 5.1).
"""

import numpy as np

PSEUDO_CODE = [
    "p    = sigmoid(Xw + b)",
    "loss = log loss(p, y)",
    "d    = X'(p - y) / n",
    "w    = w - lr * d",
]


def sigmoid(z):
    return 1 / (1 + np.exp(-np.clip(z, -500, 500)))   # clip so exp() can't overflow


def log_loss(p, y):
    p = np.clip(p, 1e-12, 1 - 1e-12)                   # log(0) is -infinity
    return -np.mean(y * np.log(p) + (1 - y) * np.log(1 - p))


def gradient_descent(X, y, lr, n_iters):
    """Yield the state after every pseudo-code line, so a Step control can run one line at a time."""
    n, d = X.shape
    w = np.zeros(d)
    b = 0.0
    for step in range(1, n_iters + 1):
        p = sigmoid(X @ w + b)
        yield {"step": step, "weights": w.copy(), "bias": b, "loss": None, "active_line": 1}

        loss = log_loss(p, y)
        yield {"step": step, "weights": w.copy(), "bias": b, "loss": loss, "active_line": 2}

        error = p - y
        grad_w = X.T @ error / n
        grad_b = error.mean()
        yield {"step": step, "weights": w.copy(), "bias": b, "loss": loss, "active_line": 3}

        w = w - lr * grad_w
        b = b - lr * grad_b
        yield {"step": step, "weights": w.copy(), "bias": b, "loss": loss, "active_line": 4}


def train(X, y, lr, n_iters):
    """Run every iteration. Returns one record per iteration (the state after line 4)."""
    return [s for s in gradient_descent(X, y, lr, n_iters) if s["active_line"] == 4]


def predict_proba(X, weights, bias):
    return sigmoid(X @ weights + bias)


def apply_threshold(probs, t=0.5):
    return (probs >= t).astype(int)
