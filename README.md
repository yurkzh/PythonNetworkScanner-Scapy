

### 📄 **README.md** (For Scapy Version)
```markdown
# 🔍 Advanced Network Scanner (Scapy)

This is a Python-based **network scanner** that detects active devices on a subnet using **Scapy**. It performs an **ARP scan** to find IP and MAC addresses of connected devices. The results can be **saved to a CSV file** for further analysis.

⚠️ **Disclaimer:** This tool is for educational and security research purposes **only**. Unauthorized scanning of networks **without permission** is illegal.

---

## 🚀 Features
✅ **Fast ARP Scanning** – Uses multi-threading for speed  
✅ **Progress Bar** – Tracks scan progress with `tqdm`  
✅ **CSV Export** – Saves discovered devices to `network_scan_results.csv`  
✅ **Safe & Legal** – Only allows private IP range scanning  

---

## 🛠️ Installation
1. Install **Python 3** if not already installed.
2. Install the required dependencies:
   ```bash
   pip install scapy tqdm
   ```
3. Run the script:
   ```bash
   python network_scanner.py
   ```

---

## 📌 Usage
1. **Run the script**:
   ```bash
   python network_scanner.py
   ```
2. **Enter the subnet to scan** (e.g., `192.168.1.0/24`).
3. **Wait for the scan to complete**.
4. **View the results** in the terminal or check `network_scan_results.csv`.

---

## 📜 Example Output
```
Enter the subnet to scan (e.g., 192.168.1.0/24): 192.168.1.0/24

🔍 Scanning network: 192.168.1.0/24...

✅ Scan Complete! Devices Found:

IP Address       MAC Address
----------------------------------------
192.168.1.1     AA:BB:CC:DD:EE:FF
192.168.1.2     11:22:33:44:55:66

📁 Results saved to network_scan_results.csv ✅
```

---

## ⚠️ Legal Disclaimer
This tool is intended **only for use on networks you own or have explicit permission to scan**. Unauthorized scanning of networks **is illegal** and may result in legal consequences. The author assumes **no responsibility** for misuse.

---

## 📜 License
This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

---

## 💡 Future Improvements
🚀 Add **port scanning**  
🔍 Implement **OS detection**  
🌎 Create a **GUI version**  

