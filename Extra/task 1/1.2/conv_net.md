# 🛡️ DDoS Detection with IP-Ratio Analysis

**Course:** CDA01 — Task 3  
**Author:** Levan Kalatozishvili  
**Log file:** [`l_kalatozishvili25_32748_server.log`](./l_kalatozishvili25_32748_server.log)

---

## Overview

This report documents the detection of DDoS attack intervals in a web server log file. The solution combines **regression-based traffic analysis** with **IP-ratio analysis** to accurately distinguish real DDoS attacks from legitimate traffic spikes.

### The Core Problem

A naive approach — flagging seconds where total requests exceed a fixed threshold — fails to tell apart:

- ✅ **Legitimate spike:** many different users visiting at the same time (high requests, high unique IPs)
- ❌ **DDoS attack:** a few IP addresses flooding the server with thousands of requests (high requests, very few unique IPs)

The key insight is to compute the **request-to-IP ratio**. During a DDoS attack this ratio spikes dramatically; during a legitimate surge it stays relatively low.

---

## Methodology

Three detection methods are applied and then combined.

### Method 1 — Traffic-Based Detection (Regression)

Requests per second are aggregated and a **linear regression** is fitted over time. Any second where traffic exceeds the regression-adjusted threshold is flagged as anomalous:

```
threshold = mean + 2.0 × std_dev
```

Linear regression reveals whether traffic is growing naturally over time, so the threshold adapts to the trend rather than treating the entire log as a flat baseline.

### Method 2 — IP-Ratio Detection

For every second, two values are computed:

- **unique IPs/sec** — how many distinct addresses made requests
- **requests/IP ratio** = total requests ÷ unique IPs

```
threshold = mean_ratio + 1.5 × std_dev
```

A high ratio means a small number of IPs is generating a disproportionate share of traffic — a strong DDoS signal. This method catches the **second DDoS interval** that Method 1 misses because its raw request volume is not extreme enough to cross the traffic threshold alone.

### Method 3 — Combined Detection

The anomalous seconds from both methods are merged with a union operation:

```python
combined_anomalies = set(traffic_anomalies) | set(ratio_anomalies)
```

Grouping rules applied to the combined set:
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
    if (ts - prev).total_seconds() > 30:   # new interval if gap > 30 s
        intervals.append((start, prev))
        start = ts
    prev = ts
intervals.append((start, prev))

# Remove noise (< 10 s)
intervals = [(s, e) for s, e in intervals if (e - s).total_seconds() >= 10]
```

---

## Results

Two DDoS intervals were detected:

| | Interval 1 | Interval 2 |
|---|---|---|
| **Detection method** | Traffic + IP-Ratio | IP-Ratio only |
| **Why Method 1 alone fails** | — | Raw req/s did not exceed the traffic threshold; only the ratio was anomalous |

> **Note:** Without the IP-ratio analysis (Method 2), the second DDoS interval is **not detected**. This is the fundamental limitation of threshold-only traffic detection.

---

## Visualizations

All plots are saved to the `task_3/` folder.

### `ddos_improved.png` — Four-panel analysis

| Panel | Content |
|---|---|
| 1 — Traffic + Regression | Requests/sec over time, linear regression trend, traffic anomalies highlighted |
| 2 — IP Diversity | Unique IPs per second — drops sharply during DDoS |
| 3 — Request/IP Ratio | Ratio over time with threshold line and flagged seconds |
| 4 — Combined Result | Final DDoS intervals shaded in red |

![DDoS Detection — Four-panel](./ddos_improved.png)

### `top_ips.png` — Top 15 IP addresses by request count

Confirms the attack pattern: a handful of IPs account for a massive share of total requests.

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

Output plots are saved to `task_3/`. Console output reports statistics and all detected intervals.

---

## Why This Approach Is More Accurate

| Limitation of traffic-only detection | How this solution addresses it |
|---|---|
| Cannot distinguish DDoS from legitimate spikes | IP-ratio analysis separates the two cases |
| Second DDoS interval goes undetected | Method 2 catches it independently |
| Single isolated anomalous seconds (noise) | Minimum 10-second interval filter |
| Fragmented intervals split by brief pauses | 30-second gap tolerance merges them |
| Non-unique timestamp index causes `.loc` errors | Boolean mask used instead of `.loc` |
