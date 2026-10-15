"""Build the VulnLab prioritization dataset (step 1 of the build plan).

Runs once, offline. Downloads three public sources, joins them on CVE ID,
adds the synthetic asset columns, derives the FIX NOW / DEFER label, and
writes data/vulnlab_prioritization.csv plus data/schema.md.

    python3 build_dataset.py            # reuse files already in data/raw/
    python3 build_dataset.py --refresh  # download fresh copies first

Sources:
    KEV   - CISA Known Exploited Vulnerabilities catalog (JSON feed)
    EPSS  - FIRST.org exploitation probability, current daily scores
    NVD   - NIST CVE records, CVSS v3 base score and vector (yearly 2.0 feeds)
"""

import argparse
import gzip
import json
import urllib.request
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd

# ---- Settings. Fixed once; recorded in schema.md. -------------------------
SEED = 42
N_ROWS = 10_000                 # all KEV rows + a random sample of the rest
NVD_YEARS = range(2018, 2027)   # CVSS v3 is consistently present from 2018
EPSS_CUTOFF = 0.01              # label rule: EPSS >= this AND internet-facing
P_INTERNET_FACING = 0.40        # synthetic: share of assets reachable from the internet

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"

ROOT = Path(__file__).parent
RAW = ROOT / "data" / "raw"
OUT_CSV = ROOT / "data" / "vulnlab_prioritization.csv"
OUT_SCHEMA = ROOT / "data" / "schema.md"


def download(refresh):
    RAW.mkdir(parents=True, exist_ok=True)
    targets = [(KEV_URL, RAW / "kev.json"), (EPSS_URL, RAW / "epss.csv.gz")]
    targets += [(NVD_URL.format(year=y), RAW / f"nvd-{y}.json.gz") for y in NVD_YEARS]
    for url, path in targets:
        if refresh or not path.exists():
            print(f"downloading {url}")
            urllib.request.urlretrieve(url, path)


def load_kev():
    kev = json.loads((RAW / "kev.json").read_text())
    return {v["cveID"] for v in kev["vulnerabilities"]}, kev["catalogVersion"]


def load_epss():
    path = RAW / "epss.csv.gz"
    with gzip.open(path, "rt") as f:
        header = f.readline().lstrip("#").strip()   # model_version:...,score_date:...
    return pd.read_csv(path, comment="#")[["cve", "epss"]], header


def load_nvd():
    """One row per CVE that has a CVSS v3.x score. Rejected CVEs are skipped."""
    rows = []
    for year in NVD_YEARS:
        feed = json.load(gzip.open(RAW / f"nvd-{year}.json.gz"))
        for item in feed["vulnerabilities"]:
            cve = item["cve"]
            if cve.get("vulnStatus") == "Rejected":
                continue
            metrics = cve.get("metrics", {})
            v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
            if not v3:
                continue
            # Prefer NVD's own (Primary) score; fall back to the CNA's.
            cvss = ([m for m in v3 if m.get("type") == "Primary"] or v3)[0]["cvssData"]
            rows.append({
                "cve_id": cve["id"],
                "cvss_base": cvss["baseScore"],
                "cvss_av_network": int(cvss["attackVector"] == "NETWORK"),
                "cvss_ac_low": int(cvss["attackComplexity"] == "LOW"),
                "cvss_pr_none": int(cvss["privilegesRequired"] == "NONE"),
                "cvss_ui_none": int(cvss["userInteraction"] == "NONE"),
            })
        del feed
    return pd.DataFrame(rows).drop_duplicates("cve_id")


def build():
    kev_ids, kev_version = load_kev()
    epss, epss_header = load_epss()
    nvd = load_nvd()

    df = nvd.merge(epss, left_on="cve_id", right_on="cve", how="inner").drop(columns="cve")
    df = df.rename(columns={"epss": "epss_score"})
    df["kev_listed"] = df["cve_id"].isin(kev_ids).astype(int)
    pool_size, pool_kev = len(df), int(df["kev_listed"].sum())

    # Keep every KEV row, then fill up to N_ROWS with a random sample of the rest.
    rng = np.random.default_rng(SEED)
    df = df.sort_values("cve_id").reset_index(drop=True)
    kev_rows = df[df["kev_listed"] == 1]
    other = df[df["kev_listed"] == 0]
    pick = rng.choice(len(other), size=N_ROWS - len(kev_rows), replace=False)
    df = pd.concat([kev_rows, other.iloc[np.sort(pick)]]).sort_values("cve_id").reset_index(drop=True)

    # Synthetic asset attributes. No real asset data is used (SRS 2.3).
    n = len(df)
    df["asset_criticality"] = rng.integers(1, 6, size=n)
    df["days_open"] = rng.integers(0, 366, size=n)
    df["internet_facing"] = (rng.random(n) < P_INTERNET_FACING).astype(int)

    # Label rule from the SDD, section 5.2.
    fix_now = (df["kev_listed"] == 1) | ((df["epss_score"] >= EPSS_CUTOFF) & (df["internet_facing"] == 1))
    df["label"] = fix_now.astype(int)

    cols = ["cve_id", "cvss_base", "cvss_av_network", "cvss_ac_low", "cvss_pr_none",
            "cvss_ui_none", "epss_score", "kev_listed", "asset_criticality", "days_open",
            "internet_facing", "label"]
    df[cols].to_csv(OUT_CSV, index=False)

    stats = {
        "built": date.today().isoformat(),
        "kev_version": kev_version,
        "epss_header": epss_header,
        "pool_size": pool_size,
        "pool_kev": pool_kev,
        "rows": n,
        "kev_rows": int(df["kev_listed"].sum()),
        "fix_now": int(df["label"].sum()),
    }
    write_schema(stats)
    print(f"wrote {OUT_CSV} ({n} rows, {stats['fix_now']} FIX NOW = {stats['fix_now'] / n:.1%})")


def write_schema(s):
    defer = s["rows"] - s["fix_now"]
    OUT_SCHEMA.write_text(f"""# VulnLab dataset schema

`vulnlab_prioritization.csv`, built {s['built']} by `build_dataset.py`.
One row is one vulnerability finding.

## Sources

| Source | Version downloaded |
|---|---|
| CISA KEV catalog | catalog version {s['kev_version']} |
| FIRST EPSS | {s['epss_header']} |
| NIST NVD CVE 2.0 feeds | years {NVD_YEARS.start}-{NVD_YEARS.stop - 1}, downloaded {s['built']} |

## Columns

| Column | Type | Range | Source | Notes |
|---|---|---|---|---|
| `cve_id` | text | - | NVD | Identifier only. Not used as a feature. |
| `cvss_base` | float | 0.0 to 10.0 | NVD | CVSS v3.x base score (NVD Primary score, else CNA score) |
| `cvss_av_network` | boolean | 0 or 1 | NVD | Attack vector is NETWORK |
| `cvss_ac_low` | boolean | 0 or 1 | NVD | Attack complexity is LOW |
| `cvss_pr_none` | boolean | 0 or 1 | NVD | Privileges required is NONE |
| `cvss_ui_none` | boolean | 0 or 1 | NVD | User interaction is NONE |
| `epss_score` | float | 0.0 to 1.0 | EPSS | Probability of exploitation in the next 30 days |
| `kev_listed` | boolean | 0 or 1 | KEV | CVE appears in the KEV catalog |
| `asset_criticality` | integer | 1 to 5 | synthetic | Uniform random, seed {SEED} |
| `days_open` | integer | 0 to 365 | synthetic | Uniform random, seed {SEED} |
| `internet_facing` | boolean | 0 or 1 | synthetic | 1 with probability {P_INTERNET_FACING}, seed {SEED} |
| `label` | boolean | 0 or 1 | derived | 1 is FIX NOW, 0 is DEFER |

## Label rule

FIX NOW when `kev_listed = 1`, or when `epss_score >= {EPSS_CUTOFF}` and
`internet_facing = 1`. Every other row is DEFER.

Result: {s['fix_now']} FIX NOW ({s['fix_now'] / s['rows']:.1%}) and {defer} DEFER ({defer / s['rows']:.1%}).

## Sampling

{s['pool_size']:,} CVEs from {NVD_YEARS.start}-{NVD_YEARS.stop - 1} have both a CVSS v3 score and
an EPSS score; {s['pool_kev']:,} of them are in KEV. The dataset keeps every KEV row and fills
the rest with a random sample (seed {SEED}) of non-KEV rows, up to {s['rows']:,} rows. Rejected
CVEs and CVEs with no CVSS v3 score are excluded.

Without the sampling, KEV rows would be about 0.5% of the data and the classes would be badly
unbalanced. The EPSS cut-off of {EPSS_CUTOFF} is close to the 75th percentile of non-KEV
EPSS scores.

## Leakage note

`kev_listed`, `epss_score`, and `internet_facing` all feed the label rule. A model given
`kev_listed` as a feature can copy it instead of learning. Training should leave it out,
and the app should use it only for the KEV readout (R23).
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true", help="download fresh copies of the sources")
    download(parser.parse_args().refresh)
    build()
