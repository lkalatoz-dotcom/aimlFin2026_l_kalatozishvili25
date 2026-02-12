import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import re

# Load the server log file
file_path = r"C:\Users\kalat\OneDrive\Desktop\final\3\l_kalatozishvili25_32748_server.txt"

# Parse log file manually (Apache/Nginx combined log format)
def parse_log_line(line):
    # Regex pattern for Apache combined log format
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

# Read and parse the file
records = []
print("Parsing log file...")
with open(file_path, 'r', encoding='utf-8') as f:
    for i, line in enumerate(f):
        parsed = parse_log_line(line)
        if parsed:
            records.append(parsed)
        if (i + 1) % 10000 == 0:
            print(f"Processed {i + 1} lines...")

df = pd.DataFrame(records)
print(f"\nTotal records parsed: {len(df)}")

# Convert timestamp to datetime
df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S%z')

# Show time range
print(f"Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
print(f"Duration: {df['timestamp'].max() - df['timestamp'].min()}")

# Set timestamp as index
df.set_index('timestamp', inplace=True)

# Resample to count requests per second
traffic_1sec = df['ip'].resample('1s').count()
traffic_1sec = traffic_1sec[traffic_1sec > 0]

print(f"\nTraffic Statistics (requests per second):")
print(f"Total seconds with traffic: {len(traffic_1sec)}")
print(f"Mean: {traffic_1sec.mean():.2f}")
print(f"Std Dev: {traffic_1sec.std():.2f}")
print(f"Max: {traffic_1sec.max()}")
print(f"Min: {traffic_1sec.min()}")

# Calculate threshold for DDoS detection
threshold = traffic_1sec.mean() + 2.0 * traffic_1sec.std()
print(f"Threshold: {threshold:.2f}")

# Find anomalies
ddos_times = traffic_1sec[traffic_1sec > threshold]

if not ddos_times.empty:
    start_time = ddos_times.index[0]
    end_time = ddos_times.index[-1]
    print(f"\n✓ DDoS Attack Detected!")
    print(f"Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"End: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Duration: {end_time - start_time}")
    print(f"Peak traffic: {ddos_times.max()} requests/second")
    print(f"Number of anomalous seconds: {len(ddos_times)}")
else:
    print("\n✗ No DDoS attack detected")

# Analyze top IPs
print(f"\nTop 10 Most Active IPs:")
top_ips = df['ip'].value_counts().head(10)
for ip, count in top_ips.items():
    percentage = (count / len(df)) * 100
    print(f"{ip}: {count} requests ({percentage:.1f}%)")

# Analyze HTTP status codes
print(f"\nHTTP Status Code Distribution:")
print(df['status'].value_counts().sort_index())

# Visualization
fig, axes = plt.subplots(3, 1, figsize=(14, 12))

# Plot 1: Traffic per second
axes[0].plot(traffic_1sec.index, traffic_1sec.values, color='blue', alpha=0.7, linewidth=0.8)
if not ddos_times.empty:
    axes[0].scatter(ddos_times.index, ddos_times.values, color='red', s=20, label='DDoS Anomalies', zorder=5)
axes[0].axhline(y=threshold, color='green', linestyle=':', linewidth=2, label=f"Threshold ({threshold:.2f})")
axes[0].axhline(y=traffic_1sec.mean(), color='orange', linestyle='--', linewidth=1, label=f"Mean ({traffic_1sec.mean():.2f})")
axes[0].set_xlabel("Time")
axes[0].set_ylabel("Requests per second")
axes[0].set_title("Web Traffic Over Time (per second)")
axes[0].legend()
axes[0].grid(True, alpha=0.3)

# Plot 2: Top 15 IPs
top_15_ips = df['ip'].value_counts().head(15)
axes[1].barh(range(len(top_15_ips)), top_15_ips.values, color='steelblue')
axes[1].set_yticks(range(len(top_15_ips)))
axes[1].set_yticklabels(top_15_ips.index, fontsize=9)
axes[1].set_xlabel("Number of requests")
axes[1].set_title("Top 15 IPs by Request Count")
axes[1].invert_yaxis()
axes[1].grid(True, alpha=0.3, axis='x')

# Plot 3: Requests distribution (histogram)
axes[2].hist(traffic_1sec.values, bins=50, color='skyblue', edgecolor='black', alpha=0.7)
axes[2].axvline(x=threshold, color='red', linestyle='--', linewidth=2, label=f"Threshold ({threshold:.2f})")
axes[2].axvline(x=traffic_1sec.mean(), color='orange', linestyle='--', linewidth=2, label=f"Mean ({traffic_1sec.mean():.2f})")
axes[2].set_xlabel("Requests per second")
axes[2].set_ylabel("Frequency")
axes[2].set_title("Distribution of Traffic Intensity")
axes[2].legend()
axes[2].grid(True, alpha=0.3)

plt.tight_layout()
plt.show()

# Save results to file
if not ddos_times.empty:
    output_file = r"C:\Users\kalat\OneDrive\Desktop\final\3\ddos_report.txt"
    with open(output_file, 'w') as f:
        f.write("DDoS ATTACK DETECTION REPORT\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Analysis Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Log File: {file_path}\n\n")
        f.write(f"Attack Period:\n")
        f.write(f"  Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  End: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Duration: {end_time - start_time}\n\n")
        f.write(f"Attack Statistics:\n")
        f.write(f"  Peak Traffic: {ddos_times.max()} requests/second\n")
        f.write(f"  Total Anomalous Seconds: {len(ddos_times)}\n")
        f.write(f"  Threshold Used: {threshold:.2f}\n\n")
        f.write(f"Top Attacking IPs:\n")
        for ip, count in top_ips.items():
            f.write(f"  {ip}: {count} requests\n")
    print(f"\n✓ Report saved to: {output_file}")