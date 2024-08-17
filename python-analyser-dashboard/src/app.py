import matplotlib.pyplot as plt
import io
import base64

from flask import Flask, render_template, request
from collections import Counter


app = Flask(__name__)

# Initialize a global variable to store the parsed data
parsed_data = None

# Parse the plain text data
def parse_packet_data(data):
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    other_count = 0
    total_size = 0
    packet_size_count = 0
    destination_ips = Counter()

    lines = data.strip().split('\n')
    for line in lines:
        if line.startswith("TCP Packets:"):
            tcp_count = int(line.split(": ")[1])
        elif line.startswith("UDP Packets:"):
            udp_count = int(line.split(": ")[1])
        elif line.startswith("ICMP Packets:"):
            icmp_count = int(line.split(": ")[1])
        elif line.startswith("Other Packets:"):
            other_count = int(line.split(": ")[1])
        elif line.startswith("Size:"):
            parts = line.split(", Count: ")
            size = int(parts[0].split(": ")[1].split()[0])
            count = int(parts[1])
            total_size += size * count
            packet_size_count += count
        elif "->" in line:
            dst_ip = line.split("->")[1].split(":")[0].strip()
            destination_ips[dst_ip] += 1

    return {
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "other_count": other_count,
        "average_packet_size": total_size / packet_size_count if packet_size_count > 0 else 0,
        "total_data_volume": total_size,
        "destination_ips": destination_ips,
    }

# Convert parsed data to images
def create_pie_chart(data):
    labels = 'TCP', 'UDP', 'ICMP', 'Other'
    sizes = [data['tcp_count'], data['udp_count'], data['icmp_count'], data['other_count']]
    colors = ['gold', 'yellowgreen', 'lightcoral', 'lightskyblue']
    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=140)
    plt.axis('equal')
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


def create_bar_chart(data):
    sorted_ips = data['destination_ips'].most_common(10)  # Top 10 IPs
    labels, counts = zip(*sorted_ips)
    plt.figure(figsize=(8, 6))
    plt.barh(labels, counts, color='skyblue')
    plt.xlabel('Frequency')
    plt.ylabel('Destination IPs')
    plt.title('Top 10 Destination IPs by Frequency')
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


@app.route('/', methods=['GET', 'POST'])
def index():
    global parsed_data
    if request.method == 'POST':
        # Receive plain text data from the Rust application
        plain_text_data = request.data.decode('utf-8')
        parsed_data = parse_packet_data(plain_text_data)
        return "Data received successfully", 200
    
    if parsed_data:
        # Generate charts and display the analysis
        pie_chart = create_pie_chart(parsed_data)
        bar_chart = create_bar_chart(parsed_data)
        return render_template('index.html', 
                               average_packet_size=parsed_data['average_packet_size'],
                               total_data_volume=parsed_data['total_data_volume'],
                               pie_chart=pie_chart,
                               bar_chart=bar_chart)
    else:
        return "No data received yet", 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
