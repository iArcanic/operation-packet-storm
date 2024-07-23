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
