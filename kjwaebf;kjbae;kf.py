import socket
import time
import logging
from scapy.all import ARP, Ether, srp, conf

logging.basicConfig(filename='network_access.log', level=logging.INFO, format='%(asctime)s - %(message)s')

registered_devices = {
    "192.168.1.10": "00:1A:2B:3C:4D:5E",
    "192.168.1.11": "00:1A:2B:3C:4D:5F",
}

def is_registered(ip):
    return ip in registered_devices

def notify_owner(ip):
    message = f"Notification: Unregistered device connected: {ip}"
    print(message)
    logging.info(message)

def check_malware(ip):
    print(f"Checking for malware on {ip}... (simulated check)")
    return False

def verify_device(ip):
    print(f"Verifying device {ip}... (simulated verification)")
    return True

def handle_new_device(ip, mac):
    if is_registered(ip):
        message = f"Access granted to {ip}"
        print(message)
        logging.info(message)
    else:
        notify_owner(ip)
        if check_malware(ip):
            message = f"Access denied to {ip} due to malware."
            print(message)
            logging.info(message)
        else:
            if verify_device(ip):
                message = f"Access granted to {ip}."
                print(message)
                logging.info(message)
                registered_devices[ip] = mac
            else:
                message = f"Access denied to {ip} due to verification failure."
                print(message)
                logging.info(message)

def scan_network():
    target_ip = "192.168.1.0/24"
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        handle_new_device(ip, mac)

while True:
    try:
        scan_network()
        time.sleep(10)
    except Exception as e:
        print(f"An error occurred: {e}")
        break