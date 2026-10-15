"""The plot builder: turns model state into matplotlib figures (SDD 5.1)."""

import matplotlib

matplotlib.use("Agg")   # draw off-screen; Streamlit displays the finished figure

import matplotlib.pyplot as plt


def loss_curve(losses, n_iters):
    """Loss against iteration (R16). The x-axis is fixed to the full run so the curve grows
    across the plot as training advances instead of rescaling every frame."""
    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.plot(range(1, len(losses) + 1), losses, color="#1f77b4", linewidth=2)
    ax.set_xlim(0, n_iters)
    ax.set_ylim(0, max(0.75, max(losses, default=0) * 1.05))
    ax.set_xlabel("iteration")
    ax.set_ylabel("log loss")
    ax.grid(alpha=0.3)
    if losses:
        ax.annotate(f"{losses[-1]:.4f}", (len(losses), losses[-1]),
                    textcoords="offset points", xytext=(6, 6), fontsize=9)
    fig.tight_layout()
    return fig
