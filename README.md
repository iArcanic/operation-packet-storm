# operation-packet-storm

iArcanic's submission to CoreTech Security's graduate challenge

## Brief

A critical situation has emerged, and we're calling on the brightest technical minds to assist. We’ve intercepted a massive data dump - 1,000,000 packets of potentially hostile network traffic. Time is of the essence, and we need your expertise to rapidly process and analyse this data before it's too late.

Your mission is to develop a high-speed program in C, C++ or Rust to process the intercepted 1,000,000 packet capture (.pcap) file. Your analysis could be the key to preventing a major cyber attack on our nation's infrastructure.

### Required intelligence

Our security hangs in the balance, and every second counts. Our analysts need to know:

1. The average packet size, and the total volume of data received during the attack
2. Destination IPs ranked by frequency, in order to identify primary targets
3. The number of packets sent with different transport layer protocols, to understand what mitigations would be most effective

You’ll need to make sure our operational support team can build your solution and verify your results, in order to gauge its operational suitability. Including documentation on expected usage and build instructions is a must.

### Terms and conditions

- The deadline for receipt of submissions is 08:00 on 26th August 2024
- All submissions must be hosted using a public code-hosting service such as GitHub
- All submissions must include a detailed README for building and verifying your solution
- All submissions must build for Ubuntu 24.04 LTS
- You may use third-party packet processing libraries like [libpcap](https://github.com/the-tcpdump-group/libpcap)

## Prerequisites

### Docker

Ensure the Docker engine is installed on your system with version **18.06.0** or higher.

You can download and install the Docker engine from the [official Docker website](https://www.docker.com/get-started/).

> [!NOTE]
>
> - Especially on Linux, make sure your user has the [required permissions](https://docs.docker.com/engine/install/linux-postinstall/) to interact with the Docker daemon.
> - If you are unable to do this, either append `sudo` in front of each `docker` command or switch to root using `sudo -s`.

### Docker Compose

Ensure that Docker Compose is installed on your system with **version 1.28.0** or higher.

You can download and install Docker Compose from the [official Docker website](https://docs.docker.com/compose/install/).

### Port availability

The [`python-analyser-dashboard`](https://github.com/iArcanic/operation-packet-storm/tree/main/python-analyser-dashboard) Docker container requires port **`5000`** to run the Flask server (default for Flask).

Ensure that this port is free and isn't running any conflicting services or have firewall rules concerning them.

## Usage

1. Clone the repository to your local machine

```bash
git clone https://github.com/iArcanic/operation-packet-storm
```

2. Download the packet capture file and place in the [pcap-files](https://github.com/iArcanic/operation-packet-storm/tree/main/pcap-files) directory

> [!IMPORTANT]
>
> - You must follow the instructions in [pcap-files/README.md](https://github.com/iArcanic/operation-packet-storm/tree/main/pcap-files) before building and running the Docker container.
> - This is to ensure you have the `packet-storm.pcap` packet capture file in the `pcap-files` directory for the Docker container to use.

3. Navigate to the project's root directory

```bash
cd operation-packet-storm
```

4. Build and run the Docker containers

```bash
docker-compose up --build
```

> [!NOTE]
> You can also use the regular Docker CLI commands like so:
>
> ```bash
> docker build -t rust-packet-analyser ./rust-packet-analyser
> docker build -t python-analyser-dashboard ./python-analyser-dashboard
> docker network create app-network
> docker run -d --name python-analyser-dashboard --network app-network -p 5000:5000 python-analyser-dashboard
> docker run -d --name rust-packet-analyser --network app-network rust-packet-analyser
> ```

5. View the Python Analyser Dashboard

```bash
http://localhost:5000
```

OR

```bash
http://127.0.0.1:5000
```

OR

```bash
http://python-analyser-dashboard:5000
```
