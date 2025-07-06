import pandas as pd
import networkx as nx
from pyvis.network import Network
from tqdm import tqdm
import ipaddress
import argparse
import os
import sys
import webbrowser
from collections import defaultdict
import json

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

def load_internal_subnets(iplist_path, log_path):
    valid = []
    with open(iplist_path) as f:
        lines = f.read().splitlines()
    with open(log_path, "w") as log:
        for line in lines:
            ip = line.strip()
            try:
                net = ipaddress.ip_network(ip if '/' in ip else ip + '/32')
                valid.append(net)
                log.write(f"[✓] Loaded: {ip}\n")
            except Exception as e:
                log.write(f"[✗] Invalid IP/subnet: {ip} ({e})\n")
    return valid

def ip_in_subnets(ip, subnets):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in subnet for subnet in subnets)
    except:
        return False

def inject_legend(html_path):
    legend_html = (
        "<div id='custom-legend' style='"
        "position: absolute; top: 20px; left: 20px; background-color: rgba(30,30,30,0.85);"
        "color: white; padding: 12px; border-radius: 10px; font-size: 14px;"
        "z-index: 1000; font-family: Arial, sans-serif;'>"
        "🧭 <b>Legend</b><br>"
        "<div style='margin-top:5px;'>🔥 <span style='color:red;'>Compromised Client</span></div>"
        "<div>🎯 <span style='color:yellow;'>Targeted Server</span></div>"
        "<div><span style='color:#56E39F;'>▲</span> Client IP</div>"
        "<div><span style='color:#F6AE2D;'>★</span> Server IP</div>"
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
    parser = argparse.ArgumentParser(description="Netflow Graph Visualizer with Compromised/Targeted IP Detection")
    parser.add_argument("--input", required=True, help="Path to Netflow Excel/CSV file")
    parser.add_argument("--iplist", required=True, help="Path to TXT file with internal subnets")
    parser.add_argument("--output", default="graph_output.html", help="Output HTML path")
    parser.add_argument("--log", default="subnet_check.log", help="Log output for IP/subnet matching")
    parser.add_argument("--meta", default="ip_metadata.json", help="Optional export of IP metadata")
    args = parser.parse_args()

    ext = os.path.splitext(args.input)[-1].lower()
    df = pd.read_excel(args.input) if ext in ['.xls', '.xlsx'] else pd.read_csv(args.input)

    internal_subnets = load_internal_subnets(args.iplist, args.log)

    net = Network(height="900px", width="100%", bgcolor="#1e1e1e", font_color="white")
    G = nx.MultiDiGraph()
    hit_counter = defaultdict(int)
    ip_metadata = {}

    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Processing Flows"):
        src_ip = str(row.get('Src IP', '')).strip()
        dst_ip = str(row.get('Dest IP', '')).strip()
        src_cc = str(row.get('Src CC', '')).strip()
        dst_cc = str(row.get('Dest CC', '')).strip()
        client_ip = str(row.get('Client IP Address', '')).strip()
        server_ip = str(row.get('Server IP', '')).strip()
        matched_ip = str(row.get('Matched IP', '')).strip()
        threat_actor = str(row.get('Threat Actor', '')).strip()

        for ip in [src_ip, dst_ip, client_ip, server_ip, matched_ip]:
            hit_counter[ip] += 1

        ip_roles = {}
        for ip, role in [(client_ip, 'Client'), (server_ip, 'Server'), (src_ip, 'Src'), (dst_ip, 'Dest'), (matched_ip, 'Matched')]:
            if ip and ip not in ip_roles:
                ip_roles[ip] = role

        for ip, role in ip_roles.items():
            cc = row.get(f'{role} CC', '') if f'{role} CC' in row else ''
            hits = hit_counter[ip]
            shape, color, status = 'dot', '#AAAAAA', ''
            label = f"{ip}\n[{cc}]" if cc else ip

            if role == 'Client':
                shape = 'triangle'
                color = '#56E39F'
                if ip_in_subnets(ip, internal_subnets):
                    color = 'red'
                    status = 'Compromised Client'
            elif role == 'Server':
                shape = 'star'
                color = '#F6AE2D'
                if ip_in_subnets(ip, internal_subnets):
                    color = 'yellow'
                    status = 'Targeted Server'
            elif role == 'Src':
                color = '#6EC1E4'
            elif role == 'Dest':
                color = '#FF9F1C'
            elif role == 'Matched':
                color = '#FF4040'

            flags = []
            if status:
                flags.append(f"Status: {status}")
            flags.append(f"Role: {role}")
            flags.append(f"IP: {ip}")
            flags.append(f"Country: {cc}")
            flags.append(f"Hits: {hits}")
            if ip == matched_ip and threat_actor:
                flags.append("Flagged by Threat Actor")

            tooltip = "\n".join(flags)
            G.add_node(ip, label=label, title=tooltip, color=color, shape=shape)
            ip_metadata[ip] = {
                "ip": ip,
                "role": role,
                "status": status,
                "country": cc,
                "hits": hits
            }

        if threat_actor:
            G.add_node(threat_actor, label=threat_actor, title="Threat Actor", color="#D7263D", shape="box")

        if client_ip and server_ip:
            if ip_in_subnets(client_ip, internal_subnets):
                G.add_edge(client_ip, server_ip, color="red", title="Compromised Flow")
            elif ip_in_subnets(server_ip, internal_subnets):
                G.add_edge(client_ip, server_ip, color="orange", title="Targeted Flow")
            else:
                G.add_edge(client_ip, server_ip, color="gray", title="General Flow")

        if threat_actor and matched_ip:
            G.add_edge(threat_actor, matched_ip, color="red", title="Associated")

    if G.number_of_nodes() == 0:
        print("[!] Graph is empty.")
        sys.exit(1)

    net.from_nx(G)
    net.set_options('{"physics": {"stabilization": {"iterations": 1000}, "barnesHut": {"gravitationalConstant": -2000}}, "layout": {"improvedLayout": true}}')
    net.save_graph(args.output)
    inject_legend(args.output)
    with open(args.meta, 'w') as meta_out:
        json.dump(ip_metadata, meta_out, indent=2)
    print(f"[+] Graph saved: {args.output}")
    print(f"[+] Subnet log saved: {args.log}")
    print(f"[+] IP metadata exported: {args.meta}")
    webbrowser.open('file://' + os.path.realpath(args.output))

if __name__ == "__main__":
    main()
