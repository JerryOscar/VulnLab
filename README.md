# VulnLab

A teaching tool that lets you watch a machine-learning model learn to sort
vulnerabilities into FIX NOW and DEFER, one step at a time.

## Run it

```bash
pip install -r requirements.txt
python3 build_dataset.py      # step 1: download KEV, EPSS, NVD and build the CSV
```

Then open `notebooks/01_numpy_training_loop.ipynb` and run it top to bottom
(steps 2 and 3: the NumPy training loop and the scikit-learn check).

## Layout

| Path | What it is |
|---|---|
| `build_dataset.py` | Offline dataset build. Writes `data/vulnlab_prioritization.csv` and `data/schema.md` |
| `data/schema.md` | Every column, its source, the label rule, and the source versions |
| `notebooks/01_numpy_training_loop.ipynb` | Gradient-descent loop as a generator, toy test, real data, scikit-learn check |

## Data sources

- CISA Known Exploited Vulnerabilities catalog
- FIRST.org Exploit Prediction Scoring System (EPSS)
- NIST National Vulnerability Database (CVSS v3)

The asset columns (`asset_criticality`, `days_open`, `internet_facing`) are
synthetic. No employer or customer data is used.
