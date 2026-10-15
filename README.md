# VulnLab

A teaching tool that lets you watch a machine-learning model learn to sort
vulnerabilities into FIX NOW and DEFER, one step at a time.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

The dataset is already in `data/`. To rebuild it from the public sources, run
`python3 build_dataset.py` (step 1: downloads KEV, EPSS, NVD and writes the CSV).

The notebook `notebooks/01_numpy_training_loop.ipynb` walks through steps 2 and 3:
the NumPy training loop and the scikit-learn check.

## Layout

| Path | What it is |
|---|---|
| `app.py` | The Streamlit page: controls, dataset summary, loss curve, learned weights |
| `engine.py` | Gradient-descent loop as a generator. Arrays in, numbers out |
| `data.py` | Reads a CSV from `data/`, picks the features, splits and scales |
| `plots.py` | matplotlib figures (loss curve) |
| `build_dataset.py` | Offline dataset build. Writes `data/vulnlab_prioritization.csv` and `data/schema.md` |
| `data/schema.md` | Every column, its source, the label rule, and the source versions |
| `notebooks/01_numpy_training_loop.ipynb` | Gradient-descent loop as a generator, toy test, real data, scikit-learn check |

## Data sources

- CISA Known Exploited Vulnerabilities catalog
- FIRST.org Exploit Prediction Scoring System (EPSS)
- NIST National Vulnerability Database (CVSS v3)

The asset columns (`asset_criticality`, `days_open`, `internet_facing`) are
synthetic. No employer or customer data is used.
