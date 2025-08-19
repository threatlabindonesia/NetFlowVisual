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
Netflow Visualizer - V6 Final Om Apip
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


def inject_controls_and_legend(html_path, actor_node_map):
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        actor_map_js = f"<script>let actorNodeMap = {json.dumps(actor_node_map)};</script>"

        controls_html = """
        <div style='position:fixed; top:10px; right:10px; background:#1e1e1e; padding:10px; color:white; border-radius:8px; z-index:9999; width:260px;'>
            <label><b>Threat Actor Filter</b></label><br>
            <div id='actorChecklist' style='max-height:250px; overflow-y:auto; background:#2e2e2e; padding:5px; border-radius:5px;'></div>
        </div>

        <div style='position:fixed; bottom:10px; left:10px; background:#1e1e1e; color:white; padding:12px; border-radius:8px; font-size:12px; z-index:9999;'>
            <b>Legend</b><br>
            🔥 Compromised (Internal → External)<br>
            🎯 Targeted (External → Internal)<br>
            <span style="color:#1f77b4;">▲</span> Client IP<br>
            <span style="color:#F6AE2D;">★</span> Server IP<br>
            <span style="color:#FF4040;">■</span> Matched IP<br>
            ⬛ Threat Actor (Red Box)<br>
        </div>

        <script>
        function buildChecklist() {
            const container = document.getElementById('actorChecklist');
            container.innerHTML = '';

            const actors = Object.keys(actorNodeMap).sort();
            actors.forEach(name => {
                const id = 'actor_' + name.replace(/[^a-zA-Z0-9]/g, '_');
                const cb = document.createElement("input");
                cb.type = "checkbox";
                cb.id = id;
                cb.name = "actor";
                cb.value = name;
                cb.checked = true;
                cb.onclick = applyActorFilter;

                const lb = document.createElement("label");
                lb.htmlFor = id;
                lb.textContent = name;

                const div = document.createElement("div");
                div.appendChild(cb);
                div.appendChild(lb);
                container.appendChild(div);
            });

            applyActorFilter();
        }

        function applyActorFilter() {
            const checkedNames = Array.from(document.querySelectorAll("input[name='actor']:checked")).map(cb => cb.value);
            const actorIdSet = new Set(checkedNames.map(name => actorNodeMap[name]));

            const nodeSet = new Set();
            const edgeSet = new Set();
            const matchedIPs = new Set();

            const allEdges = edges.get();
            const allNodes = nodes.get();

            allEdges.forEach((e, idx) => {
                if (actorIdSet.has(e.from) || actorIdSet.has(e.to)) {
                    matchedIPs.add(e.from);
                    matchedIPs.add(e.to);
                    edgeSet.add(idx);
                }
            });

            allEdges.forEach((e, idx) => {
                if (matchedIPs.has(e.from) || matchedIPs.has(e.to)) {
                    edgeSet.add(idx);
                    nodeSet.add(e.from);
                    nodeSet.add(e.to);
                }
            });

            actorIdSet.forEach(id => nodeSet.add(id));

            nodes.update(allNodes.map(n => ({ ...n, hidden: !nodeSet.has(n.id) })));
            edges.update(allEdges.map((e, idx) => ({ ...e, hidden: !edgeSet.has(idx) })));

            if (nodeSet.size === 0) {
                alert("⚠️ No matching data. Try adjusting filters.");
            }
        }

        setTimeout(() => { buildChecklist(); }, 300);
        </script>
        """

        html = html.replace("</body>", actor_map_js + controls_html + "</body>")

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

    except Exception as e:
        print(f"[!] Failed to inject UI: {e}")


def main():
    banner()

    parser = argparse.ArgumentParser(description="Netflow Visualizer V7 (Filter by Threat Actor Only)")
    parser.add_argument("--input", required=True, help="Path to Netflow CSV/XLSX")
    parser.add_argument("--iplist", required=True, help="Path to TXT file with internal subnets")
    parser.add_argument("--output", default="graph_output.html", help="Output HTML path")
    parser.add_argument("--log", default="subnet_check.log", help="Log output")
    parser.add_argument("--meta", default="ip_metadata.json", help="Exported metadata")
    args = parser.parse_args()

    ext = os.path.splitext(args.input)[-1].lower()
    df = pd.read_excel(args.input) if ext in ['.xls', '.xlsx'] else pd.read_csv(args.input)

    internal_subnets = load_internal_subnets(args.iplist, args.log)

    net = Network(height="900px", width="100%", bgcolor="#1e1e1e", font_color="white")
    G = nx.MultiDiGraph()
    hit_counter = defaultdict(int)
    ip_metadata = {}
    actor_node_map = {}

    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Processing Flows"):
        # fallback handling
        src_ip = str(row.get('src_ip_addr') or row.get('Src IP') or '').strip()
        dst_ip = str(row.get('dst_ip_addr') or row.get('Dest IP') or '').strip()
        client_ip = str(row.get('client_ip_addr') or row.get('Client IP Address') or '').strip()
        server_ip = str(row.get('server_ip_addr') or row.get('Server IP') or '').strip()
        matched_ip = str(row.get('Matched IP', '')).strip()
        threat_actor = str(row.get('Threat Actor', '')).strip()

        for ip in [src_ip, dst_ip, client_ip, server_ip, matched_ip]:
            hit_counter[ip] += 1

        ip_roles = {}
        for ip, role in [(client_ip, 'Client'), (server_ip, 'Server'), (src_ip, 'Src'), (dst_ip, 'Dest'), (matched_ip, 'Matched')]:
            if ip and ip not in ip_roles:
                ip_roles[ip] = role

        cc_map = {
            'Client': row.get('client_cc') or row.get('Client CC') or '',
            'Server': row.get('server_cc') or row.get('Server CC') or '',
            'Src': row.get('src_cc') or row.get('Src CC') or '',
            'Dest': row.get('dst_cc') or row.get('Dest CC') or '',
            'Matched': ''
        }

        for ip, role in ip_roles.items():
            if not ip or ip == threat_actor:
                continue

            cc = cc_map.get(role, '')
            flag = f"\n[{cc}]" if len(cc) == 2 and cc.isalpha() else ''
            hits = hit_counter[ip]
            shape, color, status, label_prefix = 'dot', '#AAAAAA', '', ''

            if role == 'Client':
                shape = 'triangle'
                color = '#1f77b4'
                if ip_in_subnets(ip, internal_subnets):
                    color = 'red'
                    status = 'compromised'
                    label_prefix = '🔥 '
            elif role == 'Server':
                shape = 'star'
                color = '#F6AE2D'
                if ip_in_subnets(ip, internal_subnets):
                    color = 'yellow'
                    status = 'targeted'
                    label_prefix = '🎯 '
            elif role == 'Src':
                color = '#6EC1E4'
            elif role == 'Dest':
                color = '#FF9F1C'
            elif role == 'Matched':
                color = '#FF4040'

            label = f"{label_prefix}{ip}{flag}"
            tooltip = f"Role: {role}\nIP: {ip}\nCountry: {cc}\nHits: {hits}"
            if ip == matched_ip and threat_actor:
                tooltip += f"\nFlagged by Threat Actor"

            if ip not in G.nodes:
                G.add_node(ip, label=label, title=tooltip, color=color, shape=shape, group=status)

            ip_metadata[ip] = {
                "ip": ip,
                "role": role,
                "status": status,
                "country": cc,
                "hits": hits
            }

        if threat_actor:
            if threat_actor not in G.nodes:
                G.add_node(threat_actor, label=threat_actor, color="#FF4040", title="Threat Actor",
                           shape="box", group="threat_actor", font={"color": "white"})
            actor_node_map[threat_actor] = threat_actor

        if client_ip and server_ip:
            if ip_in_subnets(client_ip, internal_subnets):
                G.add_edge(client_ip, server_ip, color="red", title="Compromised Flow", width=3, arrows="to")
            elif ip_in_subnets(server_ip, internal_subnets):
                G.add_edge(client_ip, server_ip, color="orange", title="Targeted Flow", width=3, arrows="to")
            else:
                G.add_edge(client_ip, server_ip, color="gray", title="General Flow", width=1, arrows="to")

        if threat_actor and matched_ip:
            G.add_edge(threat_actor, matched_ip, color="#FF4040", title="Associated", width=2, arrows="none")
            if server_ip:
                G.add_edge(matched_ip, server_ip, color="#FFA07A", title="Matched IP → Server", width=1, arrows="to")

    # Final patch warna threat actor di NetworkX layer
    for threat_actor in actor_node_map:
        if threat_actor in G.nodes:
            G.nodes[threat_actor]['color'] = '#FF0000'
            G.nodes[threat_actor]['shape'] = 'box'
            G.nodes[threat_actor]['group'] = 'threat_actor'
            G.nodes[threat_actor]['font'] = {"color": "white"}

    if G.number_of_nodes() == 0:
        print("[!] Graph is empty.")
        sys.exit(1)

    net.from_nx(G)

    # Final patch warna di PyVis layer
    for threat_actor in actor_node_map:
        net_node = net.get_node(threat_actor)
        if net_node:
            net_node['color'] = '#FF0000'
            net_node['shape'] = 'box'
            net_node['font'] = {"color": "white"}

    net.set_options(json.dumps({
        "physics": {
            "stabilization": {"iterations": 1000},
            "barnesHut": {"gravitationalConstant": -2000}
        },
        "layout": {"improvedLayout": True},
        "edges": {"smooth": {"type": "dynamic"}},
        "interaction": {"hover": True, "tooltipDelay": 300, "hideEdgesOnDrag": False}
    }))

    net.save_graph(args.output)
    inject_controls_and_legend(args.output, actor_node_map)

    with open(args.meta, 'w') as meta_out:
        json.dump(ip_metadata, meta_out, indent=2)

    print(f"[+] Graph saved: {args.output}")
    print(f"[+] Subnet log saved: {args.log}")
    print(f"[+] IP metadata exported: {args.meta}")

    webbrowser.open('file://' + os.path.realpath(args.output))


if __name__ == "__main__":
    main()
