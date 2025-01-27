How the Network Scanning Script Works:

The provided Python script uses the Scapy library to perform network scanning. Here’s a breakdown of its functionality:
ARP Scanning: The script sends ARP (Address Resolution Protocol) requests to all devices in a specified IP range (e.g., 192.168.1.0/24). ARP is used to map IP addresses to MAC addresses on a local network.
Device Detection: When a device responds to the ARP request, the script captures the IP and MAC addresses of the responding devices.
Device Management: The script checks if the detected device is registered in a predefined list of allowed devices. If the device is unregistered, it notifies the owner and performs checks (simulated in this case) for malware and verification.
Logging: All actions, including notifications and access grants/denials, are logged to a file for auditing and monitoring purposes.
Continuous Monitoring: The script runs in a loop, scanning the network every 10 seconds, allowing for real-time monitoring of devices connecting to the network.

Usefulness of the Script:

Network Security: The script helps in identifying unauthorized devices attempting to connect to the network, which is crucial for maintaining network security.
Monitoring: It provides continuous monitoring of the network, allowing administrators to be aware of all devices connected at any given time.
Malware Detection: Although the malware check is simulated, integrating real malware detection can help prevent infected devices from accessing the network.
Access Control: By managing a list of registered devices, the script helps enforce access control policies, ensuring that only authorized devices can connect.
Auditing: The logging feature allows for auditing of network access, which can be useful for compliance and security reviews.

Consequences of Not Using This Script:

Unauthorized Access: Without monitoring, unauthorized devices may connect to the network, leading to potential data breaches or malicious activities.
Malware Spread: Infected devices could introduce malware into the network, compromising sensitive data and systems.
Lack of Visibility: Network administrators may lack visibility into which devices are connected, making it difficult to manage and secure the network effectively.
Compliance Issues: Organizations may face compliance issues if they do not have proper access control and monitoring in place, especially in regulated industries.
Increased Risk: The overall risk of cyberattacks increases without proactive monitoring and management of network devices.


Import the repository

git clone https://github.com/BongoniDevendarGoud/Network-Scanner.git

cd Network-Scanner

pip install scapy

