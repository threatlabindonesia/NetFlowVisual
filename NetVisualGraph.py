#!/usr/bin/env python3
import pandas as pd
import networkx as nx
from pyvis.network import Network
from tqdm import tqdm
import argparse
import os
import sys

def banner():
    print(r"""
███╗   ███╗ █████╗ ██████╗ ██╗ ██████╗ 
████╗ ████║██╔══██╗██╔══██╗██║██╔════╝ 
██╔████╔██║███████║██║  ██║██║██║  ███╗
██║╚██╔╝██║██╔══██║██║  ██║██║██║   ██║
██║ ╚═╝ ██║██║  ██║██████╔╝██║╚██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝ ╚═════╝ 
   Netflow Graph Visualizer - Om Apip
""")

def get_args():
    parser = argparse.ArgumentParser(description="Visualize Netflow CSV or Excel into an interactive HTML graph with styled legend.")
    parser.add_argument("input", help="Input CSV or Excel file")
    parser.add_argument("--output", "-o", default="cymru_graph_legend.html", help="Output HTML path")
    return parser.parse_args()

def read_file_auto(filepath):
    ext = os.path.splitext(filepath)[-1].lower()
    try:
        if ext in ['.xls', '.xlsx']:
            print("[*] Detected Excel format")
            df = pd.read_excel(filepath).fillna('')
        elif ext == '.csv':
            print("[*] Detected CSV format")
            df = pd.read_csv(filepath, encoding='latin1', sep=None, engine='python').fillna('')
        else:
            raise ValueError("Unsupported file type.")
        df.columns = df.columns.str.strip()
        return df
    except Exception as e:
        print(f"[!] Failed reading file: {e}")
        sys.exit(1)

def inject_legend(html_path):
    legend_html = (
        "<div id='custom-legend' style='"
        "position: absolute; top: 20px; left: 20px; background-color: rgba(30,30,30,0.85);"
        "color: white; padding: 12px; border-radius: 10px; font-size: 14px;"
        "z-index: 1000; font-family: Arial, sans-serif;'>"
        "<b>🧭 Legend</b><br>"
        "<div style='margin-top:5px;'><span style='color:#56E39F;'>■</span> Client IP</div>"
        "<div><span style='color:#F6AE2D;'>■</span> Server IP</div>"
        "<div><span style='color:#6EC1E4;'>■</span> Src IP</div>"
        "<div><span style='color:#FF9F1C;'>■</span> Dest IP</div>"
        "<div><span style='color:#FF4040;'>■</span> Matched IP</div>"
        "<div><span style='color:#D7263D;'>■</span> Threat Actor</div>"
        "</div>"
    )
    try:
        with open(html_path, "r+", encoding="utf-8") as f:
            content = f.read()
            if "<body>" in content:
                updated = content.replace("<body>", "<body>" + legend_html, 1)
                f.seek(0)
                f.write(updated)
                f.truncate()
    except Exception as e:
        print(f"[!] Failed to inject legend: {e}")

def main():
    banner()
    args = get_args()

    args.input = os.path.abspath(args.input)
    args.output = os.path.abspath(args.output)

    if not os.path.isfile(args.input):
        print(f"[!] File not found: {args.input}")
        sys.exit(1)

    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    df = read_file_auto(args.input)

    net = Network(height="800px", width="100%", bgcolor="#1e1e1e", font_color="white")
    G = nx.MultiDiGraph()

    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Processing Rows"):
        try:
            src_ip = str(row['Src IP']).strip()
            dest_ip = str(row['Dest IP']).strip()
            client_ip = str(row['Client IP Address']).strip()
            server_ip = str(row['Server IP']).strip()
            matched_ip = str(row.get('Matched IP', '')).strip()
            threat_actor = str(row.get('Threat Actor', '')).strip()

            if not all([src_ip, dest_ip, client_ip, server_ip]):
                continue

            G.add_node(src_ip, label=src_ip, title="Source IP", color="#6EC1E4")
            G.add_node(dest_ip, label=dest_ip, title="Destination IP", color="#FF9F1C")
            G.add_node(client_ip, label=client_ip, title="Client IP (Initiator)", color="#56E39F")
            G.add_node(server_ip, label=server_ip, title="Server IP", color="#F6AE2D")

            if matched_ip:
                G.add_node(matched_ip, label=matched_ip, title="Matched IP", color="#FF4040")
            if threat_actor:
                G.add_node(threat_actor, label=threat_actor, title="Threat Actor", color="#D7263D")

            G.add_edge(client_ip, server_ip, title="Client → Server", color="#56E39F")
            G.add_edge(src_ip, dest_ip, title="Observed Flow", color="#AAAAAA")

            if threat_actor and matched_ip:
                G.add_edge(threat_actor, matched_ip, title="Associated", color="#FF4040")

            ip_roles = {
                "Client": client_ip,
                "Src": src_ip,
                "Dest": dest_ip,
                "Server": server_ip
            }
            if matched_ip:
                for role, ip in ip_roles.items():
                    if matched_ip == ip:
                        G.add_edge(matched_ip, ip, title=f"Matched as {role}", color="#FFD23F")

        except Exception as e:
            print(f"[-] Error processing row {idx}: {e}")
            continue

    print(f"[+] Graph created. Nodes: {G.number_of_nodes()} | Edges: {G.number_of_edges()}")

    try:
        net.from_nx(G)
        net.set_options('{"physics": {"stabilization": {"iterations": 1000}, "barnesHut": {"gravitationalConstant": -2000}}, "layout": {"improvedLayout": true}}')
        net.save_graph(args.output)
        inject_legend(args.output)
        if os.path.exists(args.output):
            print(f"[+] ✅ File successfully saved: {args.output}")
        else:
            print(f"[!] ❌ File save failed: {args.output} not found!")
    except Exception as e:
        print(f"[!] Failed to render graph: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
