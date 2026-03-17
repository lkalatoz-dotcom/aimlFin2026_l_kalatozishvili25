# 🛡️ DDoS Detection with IP-Ratio Analysis

**Course:** CDA01 — Task 3  
**Author:** Levan Kalatozishvili  
**Log file:** [`l_kalatozishvili25_32748_server.log`](./l_kalatozishvili25_32748_server.log)

---

## Overview

This report documents the detection of DDoS attack intervals in a web server log file covering the period **2024-03-22 18:00–19:00 (+04:00)**. The solution combines **regression-based traffic analysis** with **IP-ratio analysis** to accurately distinguish real DDoS attacks from legitimate traffic spikes.

**Total records parsed: 73,385**

### The Core Problem

A naive approach — flagging seconds where total requests exceed a fixed threshold — fails to tell apart:

- ✅ **Legitimate spike:** many different users visiting at the same time (high requests, high unique IPs → low ratio)
- ❌ **DDoS attack:** a few IP addresses flooding the server with thousands of requests (high requests, very few unique IPs → high ratio)

The key insight is to compute the **request-to-IP ratio**. During a DDoS attack this ratio spikes dramatically; during a legitimate surge it stays relatively low.

---

## Methodology

Three detection methods are applied and then combined.

### Method 1 — Traffic-Based Detection (Regression)

Requests per second are aggregated and a **linear regression** is fitted over time. Any second where traffic exceeds the threshold is flagged:

```
threshold = mean + 2.0 × std_dev
```

| Metric | Value |
|---|---|
| Mean | 20.10 req/s |
| Std Dev | 39.64 |
| Threshold | 99.39 req/s |
| Anomalies detected | 119 seconds |
| Anomaly window | 18:17:01 – 18:18:59 |

Linear regression reveals whether traffic is growing naturally over time, so the threshold adapts to the underlying trend.

### Method 2 — IP-Ratio Detection

For every second, two values are computed:

- **unique IPs/sec** — how many distinct addresses made requests
- **requests/IP ratio** = total requests ÷ unique IPs

```
threshold = mean_ratio + 1.5 × std_dev
```

| Metric | Value |
|---|---|
| Average unique IPs/sec | 16.71 |
| Average requests/IP | 1.06 |
| Std Dev | 0.13 |
| Threshold | 1.26 req/IP |
| Anomalies detected | 276 seconds |

A high ratio means a small number of IPs is generating a disproportionate share of traffic — a strong DDoS signal.

### Method 3 — Combined Detection

The anomalous seconds from both methods are merged:

```python
combined_anomalies = set(traffic_anomalies) | set(ratio_anomalies)
```

Grouping rules:
- Gap > 30 seconds between anomalies → treated as a new interval
- Intervals shorter than 10 seconds → discarded as noise

---

## Key Code Fragments

### Log Parsing

```python
def parse_log_line(line):
    pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\d+)'
    match = re.match(pattern, line)
    if match:
        return {
            'ip':        match.group(1),
            'timestamp': match.group(2),
            'request':   match.group(3),
            'status':    int(match.group(4)),
            'bytes':     int(match.group(5))
        }
    return None
```

### Regression Analysis (Method 1)

```python
traffic_1sec = df_indexed['ip'].resample('1s').count()
traffic_1sec = traffic_1sec[traffic_1sec > 0]

X = np.arange(len(traffic_1sec)).reshape(-1, 1)
y = traffic_1sec.values

model = LinearRegression()
model.fit(X, y)
trend = model.predict(X)

threshold_traffic = traffic_1sec.mean() + 2.0 * traffic_1sec.std()
ddos_traffic = traffic_1sec[traffic_1sec > threshold_traffic]
```

### IP-Ratio Analysis (Method 2)

```python
unique_ips_per_sec = df_indexed.groupby(pd.Grouper(freq='1s'))['ip'].nunique()
requests_per_sec   = df_indexed.resample('1s').size()

ratio = requests_per_sec / unique_ips_per_sec.reindex(requests_per_sec.index, fill_value=1)
ratio = ratio[ratio.notna() & (ratio > 0)]

threshold_ratio = ratio.mean() + 1.5 * ratio.std()
ddos_ratio = ratio[ratio > threshold_ratio]
```

### Combined Detection & Interval Grouping (Method 3)

```python
combined_anomalies = sorted(set(ddos_traffic.index) | set(ddos_ratio.index))

intervals = []
start = combined_anomalies[0]
prev  = start

for ts in combined_anomalies[1:]:
    if (ts - prev).total_seconds() > 30:
        intervals.append((start, prev))
        start = ts
    prev = ts
intervals.append((start, prev))

# Remove noise (< 10 s)
intervals = [(s, e) for s, e in intervals if (e - s).total_seconds() >= 10]
```

---

## Results — Detected DDoS Intervals

The combined method produced 9 candidate intervals. Analyzing the metrics, **two intervals stand out** as genuine DDoS attacks based on the request/IP ratio and traffic multiplier relative to baseline:

### ✅ Interval 3 — Moderate DDoS

| Metric | Value |
|---|---|
| **Start** | 2024-03-22 **18:14:01** |
| **End** | 2024-03-22 **18:15:59** |
| **Duration** | 118 seconds (≈ 2 min) |
| Total Requests | 6,506 |
| Unique IPs | 178 |
| **Req/IP** | **36.55** — strongly elevated |
| Peak traffic | 77 req/s |
| Average traffic | 54.67 req/s |
| Baseline | 20.10 req/s |
| **Multiplier** | **3.8×** above baseline |

> Req/IP of **36.55** is ~34× above the normal ratio of 1.06. Detected by IP-ratio analysis.

---

### ✅ Interval 4 — Primary DDoS Attack

| Metric | Value |
|---|---|
| **Start** | 2024-03-22 **18:17:01** |
| **End** | 2024-03-22 **18:18:59** |
| **Duration** | 118 seconds (≈ 2 min) |
| Total Requests | **27,265** |
| Unique IPs | **262** |
| **Req/IP** | **104.06** — extremely elevated |
| Peak traffic | **262 req/s** |
| Average traffic | 229.12 req/s |
| Baseline | 20.10 req/s |
| **Multiplier** | **13.0×** above baseline |

> Req/IP of **104.06** is ~98× above normal. Detected by **both** traffic and IP-ratio analysis. This is the primary DDoS event.

---

### ⚠️ Intervals 1–2, 5–9 — False Positives

The remaining 7 intervals have a **traffic multiplier below 1.0×** (less traffic than baseline) and very modest Req/IP ratios (1.45–4.49). These were flagged by the IP-ratio threshold because that threshold is extremely tight (mean=1.06, threshold=1.26), causing normal fluctuations to be classified as anomalies. They do **not** represent DDoS attacks.

| Interval | Req/IP | Multiplier | Verdict |
|---|---|---|---|
| 1 | 1.98 | 0.4× | ❌ False positive |
| 2 | 4.49 | 0.6× | ❌ False positive |
| **3** | **36.55** | **3.8×** | ✅ DDoS |
| **4** | **104.06** | **13.0×** | ✅ DDoS |
| 5 | 3.99 | 0.7× | ❌ False positive |
| 6 | 1.62 | 0.5× | ❌ False positive |
| 7 | 4.22 | 0.6× | ❌ False positive |
| 8 | 1.45 | 0.4× | ❌ False positive |
| 9 | 1.82 | 0.4× | ❌ False positive |

> **Root cause of false positives:** The IP-ratio threshold (`mean + 1.5 × std`) is too sensitive when the std is very small (0.13). A ratio above 1.26 is enough to trigger detection, even though this is barely above normal. Raising the multiplier to `mean + 4.0 × std` or applying a minimum absolute Req/IP floor (e.g. ≥ 5.0) would eliminate these.

---

## Summary

| | Value |
|---|---|
| Log period | 2024-03-22 18:00 – 19:00 (+04:00) |
| Total records | 73,385 |
| Baseline traffic | 20.10 req/s |
| **DDoS Interval 1** | **18:14:01 – 18:15:59** (2 min, 6,506 req, ratio 36.55) |
| **DDoS Interval 2** | **18:17:01 – 18:18:59** (2 min, 27,265 req, ratio 104.06) |

---

## Visualizations

### `ddos_improved.png` — Four-panel analysis

| Panel | Content |
|---|---|
| 1 — Traffic + Regression | Requests/sec, linear regression trend, traffic anomalies highlighted |
| 2 — IP Diversity | Unique IPs per second — drops sharply during DDoS |
| 3 — Request/IP Ratio | Ratio over time with threshold and flagged seconds |
| 4 — Combined Result | Final DDoS intervals shaded in red |

![DDoS Detection — Four-panel](./ddos_improved.png)

### `top_ips.png` — Top 15 IP addresses by request count

Confirms the attack pattern: a small number of IPs accounts for a massive share of total requests.

![Top 15 IPs](./top_ips.png)

---

## How to Reproduce

**1. Install dependencies**

```bash
pip install pandas numpy matplotlib scikit-learn
```

**2. Set the log file path** in `ddos_detection.py`:

```python
file_path = r"path/to/l_kalatozishvili25_32748_server.log"
```

**3. Run**

```bash
python ddos_detection.py
```

Plots are saved to `task_3/`. The console prints full statistics and all detected intervals.

---

## Why IP-Ratio Analysis Is Essential

| Limitation of traffic-only detection | How this solution addresses it |
|---|---|
| Cannot distinguish DDoS from legitimate spikes | IP-ratio analysis separates the two cases |
| Second DDoS interval (Interval 3) goes undetected by Method 1 alone | Method 2 catches it via the elevated ratio (36.55) |
| Isolated single-second noise | Minimum 10-second interval filter |
| Fragmented intervals | 30-second gap tolerance merges them |
