# Netflow Visualizer - by Om Apip

## Overview
Netflow Visualizer is a powerful Python-based tool for visualizing network flow (netflow) data. It builds an interactive graph from Excel/CSV netflow logs and correlates it with an internal IP/subnet list to highlight compromised clients and targeted servers. Visual styles emulate VirusTotal's threat intelligence view, and all connections are enriched with metadata such as country, role, and flow frequency.

---

## 📸 Preview

![madig_preview](https://i.imgur.com/i2RGH2z.png)
---
![madig_preview](https://i.imgur.com/Srr3Eu9.png)

---

## 🎯 Features

* Visualize client-server communication from netflow logs
* Highlight compromised clients and targeted servers based on internal IP mapping
* Automatically detects and labels threat actor associations
* Legend and node symbols for easy distinction
* Interactive tooltips with metadata: IP role, hit count, country, and compromise/target status
* Automatically exports a `.json` of IP metadata for integration or analysis

---

## 📥 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/threatlabindonesia/NetFlowVisual.git
cd NetFlowVisual
```

### 2. (Optional) Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate     # Linux/macOS
venv\Scripts\activate        # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install pandas pyvis tqdm networkx openpyxl
```

---

## 📂 Input Files

### Netflow File (Excel/CSV)

Must contain at minimum these columns:

* `Start Time`
* `Src IP`, `Src CC`
* `Dest IP`, `Dest CC`
* `Client IP Address`, `Client CC`
* `Server IP`, `Server CC`
* `Matched IP`, `Threat Actor` *(optional)*

### Internal IP List

Plaintext `.txt` file, each line:

```
192.168.0.0/24
10.0.1.5
```

Supports subnet (`/CIDR`) or single IP.

---

## 🚀 Usage

```bash
python NetVisualGraph.py \
  --input netflow.xlsx \
  --iplist internal_ips.txt \
  --output result.html \
  --log subnet_check.log \
  --meta ip_metadata.json
```

### Optional Flags

* `--output` : Path to the resulting HTML graph file
* `--log`    : Path for subnet matching log
* `--meta`   : Path to exported IP metadata JSON

---

## 📊 Output

### HTML Graph

* Interactive network graph in `result.html`
* Legend included
* Each node displays:

  * IP address
  * Role (Client, Server, Src, Dest, Matched IP)
  * Country (if available)
  * Hit count (number of flows involving this IP)
  * Status (Compromised Client or Targeted Server if applicable)

### Log File

* `subnet_check.log` logs all valid and invalid entries from your IP list

### JSON Metadata

* `ip_metadata.json` includes structured data on all nodes:

```json
{
  "192.168.0.5": {
    "ip": "192.168.0.5",
    "role": "Client",
    "status": "Compromised Client",
    "country": "ID",
    "hits": 6
  }, ...
}
```

---

## 🧪 Example

```bash
python NetflowVisualizer.py \
  --input /data/BSSN_Flow.xlsx \
  --iplist /data/internal_subnets.txt
```

Output will launch automatically in your default browser.

---

## 👤 Author

**Om Apip** – for CTI Team.
📫 Contact: [Afif Hidayatullah](https://www.linkedin.com/in/afif-hidayatullah/)

---

## 📄 License

This project is open-source and licensed under the MIT License.

---

## 🙋 FAQ

**Q: Why is my graph empty?**
A: Check if your IP list is valid. If no internal subnets match, no compromised or targeted flags will be generated.

**Q: Can I use without threat actor?**
A: Yes. That field is optional.

**Q: Does it support CSV?**
A: Yes. Both `.csv` and `.xlsx` are supported.

---

> Made with ❤️ to help defenders visualize complex flows quickly.

---

## ☕ Support
If you find this tool helpful, give it a ⭐️ or mention me in your reports 😉
