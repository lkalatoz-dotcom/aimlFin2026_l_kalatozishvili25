
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

# Save results to file in English
if not ddos_times.empty:
    output_file = r"C:\Users\kalat\OneDrive\Desktop\final\3\ddos_report.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write(" " * 20 + "DDoS ATTACK DETECTION REPORT\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("ANALYSIS INFORMATION\n")
        f.write("-" * 70 + "\n")
        f.write(f"Report Generated:        {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Log File Analyzed:       {file_path}\n")
        f.write(f"Total Records Processed: {len(df):,}\n")
        f.write(f"Log Time Range:          {df.index.min().strftime('%Y-%m-%d %H:%M:%S')} to {df.index.max().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Duration:          {df.index.max() - df.index.min()}\n\n")
        
        f.write("ATTACK DETECTION RESULTS\n")
        f.write("-" * 70 + "\n")
        f.write(f"Status:                  ✓ DDoS ATTACK DETECTED\n")
        f.write(f"Attack Start Time:       {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Attack End Time:         {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Attack Duration:         {end_time - start_time}\n")
        f.write(f"Anomalous Seconds:       {len(ddos_times)}\n\n")
        
        f.write("TRAFFIC ANALYSIS\n")
        f.write("-" * 70 + "\n")
        f.write(f"Baseline Traffic (Mean): {traffic_1sec.mean():.2f} requests/second\n")
        f.write(f"Standard Deviation:      {traffic_1sec.std():.2f} requests/second\n")
        f.write(f"Detection Threshold:     {threshold:.2f} requests/second\n")
        f.write(f"Peak Attack Traffic:     {ddos_times.max()} requests/second\n")
        f.write(f"Minimum Traffic:         {traffic_1sec.min()} requests/second\n")
        f.write(f"Maximum Traffic:         {traffic_1sec.max()} requests/second\n")
        f.write(f"Traffic Multiplier:      {ddos_times.max() / traffic_1sec.mean():.1f}x above baseline\n\n")
        
        f.write("TOP 20 ATTACKING IP ADDRESSES\n")
        f.write("-" * 70 + "\n")
        f.write(f"{'Rank':<6} {'IP Address':<20} {'Requests':<12} {'Percentage':<12}\n")
        f.write("-" * 70 + "\n")
        top_20_ips = df['ip'].value_counts().head(20)
        for rank, (ip, count) in enumerate(top_20_ips.items(), 1):
            percentage = (count / len(df)) * 100
            f.write(f"{rank:<6} {ip:<20} {count:<12,} {percentage:<11.2f}%\n")
        
        f.write("\n")
        f.write("HTTP STATUS CODE DISTRIBUTION\n")
        f.write("-" * 70 + "\n")
        f.write(f"{'Status Code':<15} {'Count':<12} {'Percentage':<12}\n")
        f.write("-" * 70 + "\n")
        status_counts = df['status'].value_counts().sort_index()
        for status, count in status_counts.items():
            percentage = (count / len(df)) * 100
            f.write(f"{status:<15} {count:<12,} {percentage:<11.2f}%\n")
        
        f.write("\n")
        f.write("ATTACK PATTERN ANALYSIS\n")
        f.write("-" * 70 + "\n")
        
        # Analyze request methods during attack
        attack_requests = df.loc[start_time:end_time]
        f.write(f"Total Requests During Attack: {len(attack_requests):,}\n")
        
        # Extract HTTP methods from requests
        attack_requests_reset = attack_requests.reset_index()
        attack_requests_reset['method'] = attack_requests_reset['request'].str.split().str[0]
        method_counts = attack_requests_reset['method'].value_counts()
        
        f.write(f"\nHTTP Methods Used During Attack:\n")
        for method, count in method_counts.items():
            percentage = (count / len(attack_requests)) * 100
            f.write(f"  {method:<10} {count:>6,} requests ({percentage:>5.1f}%)\n")
        
        # Most targeted endpoints
        attack_requests_reset['endpoint'] = attack_requests_reset['request'].str.split().str[1]
        endpoint_counts = attack_requests_reset['endpoint'].value_counts().head(10)
        
        f.write(f"\nTop 10 Targeted Endpoints During Attack:\n")
        for endpoint, count in endpoint_counts.items():
            percentage = (count / len(attack_requests)) * 100
            f.write(f"  {endpoint:<40} {count:>6,} ({percentage:>5.1f}%)\n")
        
        f.write("\n")
        f.write("RECOMMENDATIONS\n")
        f.write("-" * 70 + "\n")
        f.write("1. Implement rate limiting for the identified IP addresses\n")
        f.write("2. Configure firewall rules to block or throttle suspicious IPs\n")
        f.write("3. Enable CAPTCHA for high-traffic endpoints\n")
        f.write("4. Consider implementing a Web Application Firewall (WAF)\n")
        f.write("5. Set up real-time monitoring and alerting systems\n")
        f.write("6. Review and strengthen DDoS mitigation strategies\n")
        f.write("7. Contact ISP/hosting provider if attack persists\n")
        
        f.write("\n")
        f.write("=" * 70 + "\n")
        f.write(" " * 25 + "END OF REPORT\n")
        f.write("=" * 70 + "\n")
    
    print(f"\n✓ Detailed report saved to: {output_file}")
else:
    print("\n✗ No DDoS attack detected - report not generated")
