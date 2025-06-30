# 🔍 MADIG - Netflow Graph Visualizer

**MADIG** (Malicious Activity Directed-Graph) is a CLI-powered visualizer that converts Netflow logs (CSV/Excel) into an interactive HTML network graph — just like VirusTotal style!

> Developed with ❤️ by **Om Apip** for CTI & network forensic analysts.

---

## 🎯 Features

- ✅ Support for CSV and Excel (.xlsx/.xls)
- ✅ Interactive graph output (HTML with drag/zoom physics)
- ✅ Automatically distinguishes:
  - Client IP (real originator)
  - Server IP (destination)
  - Source/Destination IP (as seen from packet)
  - Matched IP (from threat enrichment)
  - Threat Actor
- ✅ Auto legend with color code
- ✅ CLI arguments: `--help`, `--output`
- ✅ Progress bar with speed stats
- ✅ Custom banner + error handling

---

## 📸 Preview

![madig_preview](https://i.imgur.com/i2RGH2z.png)
---
![madig_preview](https://i.imgur.com/Srr3Eu9.png)

---

## 📦 Requirements

- Python 3.8+
- pandas
- networkx
- pyvis
- tqdm
- openpyxl (for Excel support)

Install all dependencies:

```bash
pip install -r requirements.txt
````

### `requirements.txt` content:

```txt
pandas
networkx
pyvis
tqdm
openpyxl
```

---

## ⚙️ Installation

1. Clone the repo or download the script:

```bash
git clone https://github.com/threatlabindonesia/NetFlowVisual.git
cd NetFlowVisual
```

2. Make it executable (optional):

```bash
chmod +x NetVisualGraph.py
```

---

## 🚀 Usage

```bash
python NetVisualGraph.py <your_file.xlsx|csv> --output result.html
```

### Example:

```bash
python NetVisualGraph.py ./samples/netflow.xlsx --output output_graph.html
```

---

## 🧠 Input Format

Your Excel/CSV must have these **columns** (exact name or similar):

```text
Start Time, Src IP, Dest IP, Src Port, Dest Port, Client IP Address, Server IP,
Matched IP, Threat Actor
```

Even better if you also include:

* TCP Flags
* Bytes
* Sample Algo
* Src/Dest Country Code (optional)

---

## 📄 Output

A standalone `HTML` file will be created (default: `cymru_graph_legend.html`) which you can:

* Open in your browser
* Send to others (no server needed)
* Integrate with SOC dashboards

---

## 📚 Legend (Color Code)

| Role         | Color       |
| ------------ | ----------- |
| Client IP    | 🟩 Green    |
| Server IP    | 🟨 Yellow   |
| Src IP       | 🟦 Blue     |
| Dest IP      | 🟧 Orange   |
| Matched IP   | 🟥 Red      |
| Threat Actor | 🟥 Dark Red |

---

## 💡 Tips

* For best result, clean your Excel headers first.
* You can enrich `Matched IP` using threat intel feeds (e.g., AbuseIPDB, VirusTotal, MISP).
* The tool does not need internet access to run.

---

## 🧑‍💻 Author

**Om Apip** – Cyber Threat Intelligence Analyst

📫 Contact: [Afif Hidayatullah](https://www.linkedin.com/in/afif-hidayatullah/)

---

## 📄 License

MIT License. Use freely for research, educational, or operational CTI purposes.

---

## ☕ Support
If you find this tool helpful, give it a ⭐️ or mention me in your reports 😉
