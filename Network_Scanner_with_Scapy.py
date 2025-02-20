import csv
import threading
import ipaddress
from scapy.all import ARP, Ether, srp, conf
from tqdm import tqdm

# Suppress Scapy warnings to avoid excessive output
conf.verb = 0  # Disable verbose mode for Scapy (no unnecessary logs)

def scan_ip(ip):
    """
    Sends an ARP request to a single IP and returns the response.

    Parameters:
    ip (str): The target IP address to scan.

    Returns:
    dict: A dictionary containing the IP and MAC address of the discovered device.
    """
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = srp(packet, timeout=1, verbose=False)[0]

    for sent, received in result:
        return {'ip': received.psrc, 'mac': received.hwsrc}  # Device details

    return None  # No response means the IP is inactive

def validate_ip_range(ip_range):
    """
    Validates the given IP range to ensure it falls within private address space.

    Parameters:
    ip_range (str): The target subnet (e.g., "192.168.1.1/24").

    Returns:
    bool: True if the subnet is private, False otherwise.
    """
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        if network.is_private:
            return True
        else:
            print("\n⚠️  Error: Public IP ranges are not allowed for scanning.\n")
            return False
    except ValueError:
        print("\n⚠️  Error: Invalid IP range format. Use CIDR notation (e.g., 192.168.1.0/24).\n")
        return False

def network_scan(ip_range):
    """
    Scans a network range using multi-threading and displays discovered devices.

    Parameters:
    ip_range (str): The target subnet (e.g., "192.168.1.1/24").
    """
    print(f"\n🔍 Scanning network: {ip_range}...\n")

    subnet = ip_range.split('/')[0].rsplit('.', 1)[0]  # Extracts base IP
    num_ips = 256 if "/24" in ip_range else 16  # Limits scan size

    devices = []
    threads = []

    with tqdm(total=num_ips, desc="Scanning", unit="IP") as progress:
        def worker(ip):
            device = scan_ip(ip)
            if device:
                devices.append(device)
            progress.update(1)

        for i in range(1, num_ips):
            ip = f"{subnet}.{i}"
            thread = threading.Thread(target=worker, args=(ip,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    print("\n✅ Scan Complete! Devices Found:\n")
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")

    save_to_csv(devices)

def save_to_csv(devices, filename="network_scan_results.csv"):
    """
    Saves scan results to a CSV file.

    Parameters:
    devices (list): A list of dictionaries containing IP and MAC addresses.
    filename (str): The output CSV file name.
    """
    if not devices:
        print("\n⚠️  No devices found, skipping CSV export.\n")
        return

    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "MAC Address"])
        for device in devices:
            writer.writerow([device["ip"], device["mac"]])

    print(f"\n📁 Results saved to {filename} ✅\n")

if __name__ == "__main__":
    print("⚠️  DISCLAIMER: This tool is for educational purposes only. Unauthorized network scanning is illegal.\n")
    
    target_subnet = input("Enter the subnet to scan (e.g., 192.168.1.0/24): ").strip()

    if validate_ip_range(target_subnet):
        network_scan(target_subnet)
    else:
        print("❌ Scan aborted due to invalid input.")
