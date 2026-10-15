"""VulnLab: watch a model learn to sort vulnerabilities into FIX NOW and DEFER.

Build step 4: pick a dataset, set the learning rate and iteration limit, press Train, and
watch the loss curve fall.

    streamlit run app.py

Streamlit re-runs this whole script on every click, so anything that must survive a click
(the trained model) lives in st.session_state (SDD 2.2).
"""

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

import data
import engine
import plots

LEARNING_RATES = [0.001, 0.01, 0.05, 0.1, 0.5, 1.0]
FRAMES = 60   # how many times the loss curve is redrawn during one Train run

st.set_page_config(page_title="VulnLab", layout="wide")


@st.cache_data
def prepare(name):
    X, y, features = data.load_dataset(name)
    X_train, X_test, y_train, y_test = data.split_and_scale(X, y)
    return X_train, X_test, y_train, y_test, features


def draw(placeholder, losses, n_iters):
    fig = plots.loss_curve(losses, n_iters)
    placeholder.pyplot(fig)
    plt.close(fig)


if "model" not in st.session_state:
    st.session_state.model = None   # filled in by Train, cleared by Reset
model = st.session_state.model
trained = model is not None

# ---- Sidebar: the controls. Settings lock once trained (R9); Reset unlocks them (R8). ----
with st.sidebar:
    st.header("Controls")
    st.selectbox("Dataset", data.list_datasets(), key="dataset", disabled=trained)
    st.select_slider("Learning rate", LEARNING_RATES, value=0.5, key="lr", disabled=trained)
    st.slider("Iterations", 50, 2000, 1000, step=50, key="n_iters", disabled=trained)
    train_clicked = st.button("Train", type="primary", disabled=trained)
    if st.button("Reset", disabled=not trained):
        st.session_state.model = None
        st.rerun()
    if trained:
        st.caption("Press Reset to change the settings and train again.")

name = model["dataset"] if trained else st.session_state.dataset
lr = model["lr"] if trained else st.session_state.lr
n_iters = model["n_iters"] if trained else st.session_state.n_iters

# ---- The dataset (R3) ----
st.title("VulnLab")
st.markdown("Watch a model learn to sort vulnerabilities into **FIX NOW** and **DEFER**.")

df = data.read_csv(name)
X_train, X_test, y_train, y_test, features = prepare(name)
fix_now = int(df[data.LABEL].sum())

c1, c2, c3, c4 = st.columns(4)
c1.metric("Rows", f"{len(df):,}")
c2.metric("FIX NOW", f"{fix_now:,} ({fix_now / len(df):.1%})")
c3.metric("DEFER", f"{len(df) - fix_now:,}")
c4.metric("Training rows", f"{len(y_train):,}")

with st.expander("Columns"):
    st.markdown("**Features the model sees:** " + ", ".join(f"`{f}`" for f in features))
    unused = [c for c in df.columns if c not in features]
    st.markdown("**Not used for training:** " + ", ".join(f"`{c}`" for c in unused))
    st.caption("`label` is the answer. `kev_listed` is held out because the label is built from "
               "it, so the model could copy it instead of learning. Text columns are ignored.")

# ---- Training and the loss curve (R6, R10, R16) ----
st.subheader("Loss curve")
status = st.empty()
chart = st.empty()

if train_clicked:
    every = max(1, n_iters // FRAMES)
    losses = []
    for state in engine.gradient_descent(X_train, y_train, lr, n_iters):
        if state["active_line"] != 4:   # one record per iteration, after the weight update
            continue
        losses.append(state["loss"])
        if state["step"] % every == 0 or state["step"] == n_iters:
            status.markdown(f"Training... iteration **{state['step']:,}** of {n_iters:,}")
            draw(chart, losses, n_iters)
    st.session_state.model = {"dataset": name, "lr": lr, "n_iters": n_iters, "losses": losses,
                              "weights": state["weights"], "bias": state["bias"]}
    st.rerun()

if trained:
    losses = model["losses"]
    with status.container():
        c1, c2, c3 = st.columns(3)
        c1.metric("Iteration", f"{len(losses):,} of {n_iters:,}")
        c2.metric("Loss", f"{losses[-1]:.4f}", delta=f"{losses[-1] - losses[0]:.4f} since start",
                  delta_color="inverse")
        c3.metric("Learning rate", lr)
    draw(chart, losses, n_iters)

    st.subheader("What it learned")
    weights = pd.DataFrame({"weight": model["weights"]}, index=features)
    weights = weights.sort_values("weight", ascending=False)
    weights.loc["bias"] = model["bias"]
    st.dataframe(weights.style.format("{:+.3f}"))
    st.caption("Positive pushes toward FIX NOW, negative toward DEFER, near 0 means the model "
               "learned to ignore that feature. Features are scaled, so the sizes compare fairly.")
else:
    status.markdown("Iteration **0**. Press **Train** to start.")
    draw(chart, [], n_iters)
