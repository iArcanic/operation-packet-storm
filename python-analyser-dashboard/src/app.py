from flask import Flask, request, render_template


app = Flask(__name__)

# Initialize with empty data
data = {
    "summary": "",
    "packet_size_histogram": "",
    "tcp_flows": "",
    "http_payloads": ""
}


@app.route('/')
def index():
    # Render the template with the latest data received
    return render_template('index.html',
                           summary=data['summary'],
                           packet_size_histogram=data['packet_size_histogram'],
                           tcp_flows=data['tcp_flows'],
                           http_payloads=data['http_payloads'])


@app.route('/', methods=['POST'])
def update_data():
    global data
    # Get the plain text data from the request
    try:
        text_data = request.data.decode('utf-8')  # Decode the plain text data
        # Split the data into sections based on known headers
        sections = text_data.split('\n\n')
        
        if len(sections) >= 4:
            data['summary'] = sections[0]
            data['packet_size_histogram'] = sections[1]
            data['tcp_flows'] = sections[2]
            data['http_payloads'] = sections[3]
        
        return "Data updated successfully", 200

    except Exception as e:
        return str(e), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
