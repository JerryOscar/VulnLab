# VulnLab dataset schema

`vulnlab_prioritization.csv`, built 2026-10-05 by `build_dataset.py`.
One row is one vulnerability finding.

## Sources

| Source | Version downloaded |
|---|---|
| CISA KEV catalog | catalog version 2026.10.04 |
| FIRST EPSS | model_version:v2026.06.15,score_date:2026-10-05T12:00:23Z |
| NIST NVD CVE 2.0 feeds | years 2018-2026, downloaded 2026-10-05 |

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
| `asset_criticality` | integer | 1 to 5 | synthetic | Uniform random, seed 42 |
| `days_open` | integer | 0 to 365 | synthetic | Uniform random, seed 42 |
| `internet_facing` | boolean | 0 or 1 | synthetic | 1 with probability 0.4, seed 42 |
| `label` | boolean | 0 or 1 | derived | 1 is FIX NOW, 0 is DEFER |

## Label rule

FIX NOW when `kev_listed = 1`, or when `epss_score >= 0.01` and
`internet_facing = 1`. Every other row is DEFER.

Result: 2264 FIX NOW (22.6%) and 7736 DEFER (77.4%).

## Sampling

269,888 CVEs from 2018-2026 have both a CVSS v3 score and
an EPSS score; 1,386 of them are in KEV. The dataset keeps every KEV row and fills
the rest with a random sample (seed 42) of non-KEV rows, up to 10,000 rows. Rejected
CVEs and CVEs with no CVSS v3 score are excluded.

Without the sampling, KEV rows would be about 0.5% of the data and the classes would be badly
unbalanced. The EPSS cut-off of 0.01 is close to the 75th percentile of non-KEV
EPSS scores.

## Leakage note

`kev_listed`, `epss_score`, and `internet_facing` all feed the label rule. A model given
`kev_listed` as a feature can copy it instead of learning. Training should leave it out,
and the app should use it only for the KEV readout (R23).
