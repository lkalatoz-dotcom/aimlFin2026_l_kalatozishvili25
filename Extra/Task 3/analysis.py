"""
Task 3: DDoS Detection with IP-Ratio Analysis
Improved version that detects BOTH DDoS intervals
Author: Levan Kalatozishvili
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import re
from sklearn.linear_model import LinearRegression
import os

print("="*80)
print(" "*20 + "DDoS DETECTION - IMPROVED METHOD")
print("="*80)

# ============================================================================
# STEP 1: Load and Parse Log File
# ============================================================================
file_path = r"C:\dev\projectsml\cda01\extra\Task 3\l_kalatozishvili25_32748_server.txt"

def parse_log_line(line):
    pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\d+)'
    match = re.match(pattern, line)
    if match:
        return {
            'ip': match.group(1),
            'timestamp': match.group(2),
            'request': match.group(3),
            'status': int(match.group(4)),
            'bytes': int(match.group(5))
        }
    return None

print("\n[STEP 1] Parsing log file...")
records = []
with open(file_path, 'r', encoding='utf-8') as f:
    for i, line in enumerate(f):
        parsed = parse_log_line(line)
        if parsed:
            records.append(parsed)
        if (i + 1) % 10000 == 0:
            print(f"  Processed {i + 1} lines...")

df = pd.DataFrame(records)
df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S%z')

# ⭐ FIX: Don't set timestamp as index yet (to avoid duplicate issues)
print(f"\nTotal records: {len(df)}")
print(f"Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")

# ============================================================================
# METHOD 1: Traffic-Based Detection (Original - with regression)
# ============================================================================
print("\n" + "="*80)
print("METHOD 1: TRAFFIC-BASED DETECTION (with regression)")
print("="*80)

# Set index for resampling
df_indexed = df.set_index('timestamp')

traffic_1sec = df_indexed['ip'].resample('1s').count()
traffic_1sec = traffic_1sec[traffic_1sec > 0]

# Regression analysis
X = np.arange(len(traffic_1sec)).reshape(-1, 1)
y = traffic_1sec.values
model = LinearRegression()
model.fit(X, y)
trend = model.predict(X)

threshold_traffic = traffic_1sec.mean() + 2.0 * traffic_1sec.std()

print(f"Traffic Statistics:")
print(f"  Mean: {traffic_1sec.mean():.2f} req/s")
print(f"  Std Dev: {traffic_1sec.std():.2f}")
print(f"  Threshold: {threshold_traffic:.2f} req/s")

ddos_traffic = traffic_1sec[traffic_1sec > threshold_traffic]
print(f"  Anomalies detected: {len(ddos_traffic)} seconds")

if not ddos_traffic.empty:
    print(f"  First: {ddos_traffic.index[0].strftime('%H:%M:%S')}")
    print(f"  Last: {ddos_traffic.index[-1].strftime('%H:%M:%S')}")

# ============================================================================
# METHOD 2: IP-Ratio Detection (IMPROVED)
# ============================================================================
print("\n" + "="*80)
print("METHOD 2: IP-RATIO DETECTION (IMPROVED)")
print("="*80)

# Count unique IPs per second
unique_ips_per_sec = df_indexed.groupby(pd.Grouper(freq='1s'))['ip'].nunique()
unique_ips_per_sec = unique_ips_per_sec[unique_ips_per_sec > 0]

# Calculate requests per unique IP
requests_per_sec = df_indexed.resample('1s').size()
ratio = requests_per_sec / unique_ips_per_sec.reindex(requests_per_sec.index, fill_value=1)
ratio = ratio[ratio.notna() & (ratio > 0)]

# Proper threshold calculation
threshold_ratio = ratio.mean() + 1.5 * ratio.std()

print(f"IP-Ratio Statistics:")
print(f"  Average unique IPs/sec: {unique_ips_per_sec.mean():.2f}")
print(f"  Average requests per IP: {ratio.mean():.2f}")
print(f"  Std Dev: {ratio.std():.2f}")
print(f"  Threshold: {threshold_ratio:.2f} req/IP")

ddos_ratio = ratio[ratio > threshold_ratio]
print(f"  Anomalies detected: {len(ddos_ratio)} seconds")

if not ddos_ratio.empty:
    print(f"  First: {ddos_ratio.index[0].strftime('%H:%M:%S')}")
    print(f"  Last: {ddos_ratio.index[-1].strftime('%H:%M:%S')}")

# ============================================================================
# METHOD 3: COMBINED DETECTION
# ============================================================================
print("\n" + "="*80)
print("METHOD 3: COMBINED DETECTION (Traffic + IP-Ratio)")
print("="*80)

# Combine both methods
combined_anomalies = sorted(set(ddos_traffic.index) | set(ddos_ratio.index))

if combined_anomalies:
    # Group into intervals (gap > 30 seconds = new interval)
    intervals = []
    start = combined_anomalies[0]
    prev = start

    for ts in combined_anomalies[1:]:
        if (ts - prev).total_seconds() > 30:  # Increased from 10 to reduce fragmentation
            intervals.append((start, prev))
            start = ts
        prev = ts
    intervals.append((start, prev))

    # Filter out very short intervals (< 10 seconds)
    intervals = [(s, e) for s, e in intervals if (e - s).total_seconds() >= 10]

    print(f"✓ {len(intervals)} DDoS interval(s) detected:\n")

    for i, (start, end) in enumerate(intervals, 1):
        duration = (end - start).total_seconds()

        # ⭐ FIX: Use boolean indexing instead of .loc with non-unique index
        mask = (df['timestamp'] >= start) & (df['timestamp'] <= end)
        interval_data = df[mask]

        # Get traffic for this interval
        interval_traffic = traffic_1sec[(traffic_1sec.index >= start) & (traffic_1sec.index <= end)]

        unique_ips = interval_data['ip'].nunique()
        total_requests = len(interval_data)
        peak = interval_traffic.max() if len(interval_traffic) > 0 else 0
        avg = interval_traffic.mean() if len(interval_traffic) > 0 else 0

        print(f"INTERVAL {i}:")
        print(f"  Start:      {start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  End:        {end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Duration:   {duration:.0f} seconds ({duration/60:.1f} min)")
        print(f"  Requests:   {total_requests:,}")
        print(f"  Unique IPs: {unique_ips}")
        print(f"  Req/IP:     {total_requests/unique_ips:.2f}")
        print(f"  Peak:       {peak:.0f} req/s")
        print(f"  Average:    {avg:.2f} req/s")
        print(f"  Baseline:   {traffic_1sec.mean():.2f} req/s")
        print(f"  Multiplier: {peak/traffic_1sec.mean():.1f}x")
        print()
else:
    print("✗ No DDoS intervals detected")

# ============================================================================
# VISUALIZATION
# ============================================================================
print("Creating visualizations...")

os.makedirs('task_3', exist_ok=True)

fig, axes = plt.subplots(4, 1, figsize=(16, 16))

# Plot 1: Traffic with regression
axes[0].plot(traffic_1sec.index, y, color='blue', alpha=0.6, linewidth=1, label='Actual traffic')
axes[0].plot(traffic_1sec.index, trend, color='red', linestyle='--', linewidth=2, label='Regression trend')
axes[0].axhline(threshold_traffic, color='green', linestyle=':', linewidth=2, label=f'Threshold ({threshold_traffic:.2f})')
axes[0].axhline(traffic_1sec.mean(), color='orange', linestyle='--', linewidth=1, label=f'Mean ({traffic_1sec.mean():.2f})')

if not ddos_traffic.empty:
    axes[0].scatter(ddos_traffic.index, ddos_traffic.values, color='red', s=20,
                   label=f'Traffic anomalies ({len(ddos_traffic)})', zorder=5, alpha=0.7)

axes[0].set_ylabel('Requests/second', fontsize=11)
axes[0].set_title('Method 1: Traffic-Based Detection (with Regression)', fontweight='bold', fontsize=12)
axes[0].legend(loc='upper left', fontsize=9)
axes[0].grid(True, alpha=0.3)

# Plot 2: Unique IPs per second
axes[1].plot(unique_ips_per_sec.index, unique_ips_per_sec.values, color='purple', alpha=0.7)
axes[1].axhline(unique_ips_per_sec.mean(), color='orange', linestyle='--',
               label=f'Mean ({unique_ips_per_sec.mean():.2f})')
axes[1].set_ylabel('Unique IPs/second', fontsize=11)
axes[1].set_title('IP Diversity Over Time', fontweight='bold', fontsize=12)
axes[1].legend(fontsize=9)
axes[1].grid(True, alpha=0.3)

# Plot 3: Requests/IP ratio
axes[2].plot(ratio.index, ratio.values, color='orange', alpha=0.7, linewidth=1, label='Requests per IP')
axes[2].axhline(threshold_ratio, color='green', linestyle=':', linewidth=2,
               label=f'Threshold ({threshold_ratio:.2f})')
axes[2].axhline(ratio.mean(), color='blue', linestyle='--', linewidth=1,
               label=f'Mean ({ratio.mean():.2f})')

if not ddos_ratio.empty:
    axes[2].scatter(ddos_ratio.index, ddos_ratio.values, color='red', s=20,
                   label=f'Ratio anomalies ({len(ddos_ratio)})', zorder=5, alpha=0.7)

axes[2].set_ylabel('Requests per unique IP', fontsize=11)
axes[2].set_title('Method 2: IP-Ratio Detection (Distinguishes DDoS from Legitimate Spike)',
                 fontweight='bold', fontsize=12)
axes[2].legend(fontsize=9)
axes[2].grid(True, alpha=0.3)

# Plot 4: Combined - Final result
axes[3].plot(traffic_1sec.index, traffic_1sec.values, color='blue', alpha=0.5, linewidth=1, label='Traffic')
axes[3].axhline(traffic_1sec.mean(), color='orange', linestyle='--', linewidth=1, label='Baseline')

# Highlight intervals
if intervals:
    for idx, (start, end) in enumerate(intervals):
        axes[3].axvspan(start, end, alpha=0.3, color='red',
                       label=f'DDoS Interval {idx+1}' if idx == 0 else '')
        mid = start + (end - start) / 2
        peak_val = traffic_1sec[(traffic_1sec.index >= start) & (traffic_1sec.index <= end)].max() if len(traffic_1sec[(traffic_1sec.index >= start) & (traffic_1sec.index <= end)]) > 0 else 0
        axes[3].text(mid, peak_val + 10, f'Interval {idx+1}', ha='center', fontsize=9,
                    fontweight='bold', bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.7))

axes[3].set_xlabel('Time', fontsize=11)
axes[3].set_ylabel('Requests/second', fontsize=11)
axes[3].set_title('Method 3: Combined Detection - Final Result', fontweight='bold', fontsize=12)
axes[3].legend(fontsize=9)
axes[3].grid(True, alpha=0.3)

for ax in axes:
    ax.tick_params(axis='x', rotation=45)

plt.tight_layout()
plt.savefig('task_3/ddos_improved.png', dpi=300, bbox_inches='tight')
print("✓ Saved: task_3/ddos_improved.png")
plt.show()

# Top IPs
top_ips = df['ip'].value_counts().head(15)

fig2, ax = plt.subplots(figsize=(10, 6))
ax.barh(range(len(top_ips)), top_ips.values, color='steelblue')
ax.set_yticks(range(len(top_ips)))
ax.set_yticklabels(top_ips.index, fontsize=9)
ax.invert_yaxis()
ax.set_xlabel("Number of requests")
ax.set_title("Top 15 IPs by Request Count", fontweight='bold')
ax.grid(True, alpha=0.3, axis='x')
plt.tight_layout()
plt.savefig('task_3/top_ips.png', dpi=300, bbox_inches='tight')
print("✓ Saved: task_3/top_ips.png")
plt.close()

print("\n" + "="*80)
print("ANALYSIS COMPLETE!")
print("="*80)

if intervals:
    print(f"\nSummary: {len(intervals)} DDoS interval(s) detected")
    print(f"Total anomalous seconds: {len(combined_anomalies)}")