"""
Génère le schéma d'architecture SIEM/SOAR - Projet CDG Capital.
Sortie : architecture_siem_soar.png / .svg
"""
import graphviz

g = graphviz.Digraph("SIEM_SOAR_CDG_Capital", format="png")
g.attr(rankdir="LR", fontname="Helvetica", fontsize="11", bgcolor="white",
       label="Architecture SIEM/SOAR - CDG Capital (Projet PFE EMSI Marrakech)",
       labelloc="t", fontsize_title="18", pad="0.4")
g.attr("node", fontname="Helvetica", fontsize="10", style="filled")
g.attr("edge", fontname="Helvetica", fontsize="9")

# -------------------- Cluster 1 : Sources de logs --------------------
with g.subgraph(name="cluster_sources") as c:
    c.attr(label="Sources de donnees (perimetre CDG Capital)", style="rounded,filled",
           fillcolor="#EAF2FB", color="#2E6DA4", fontsize="12")
    c.node("ad", "Active Directory\n(comptes / auth)", shape="box3d", fillcolor="#BBD8F0")
    c.node("trading", "Plateforme Trading\n/ Back-office", shape="box3d", fillcolor="#BBD8F0")
    c.node("endpoints", "Postes de travail\n& Serveurs", shape="box3d", fillcolor="#BBD8F0")
    c.node("net", "Firewall / VPN\n/ Proxy", shape="box3d", fillcolor="#BBD8F0")
    c.node("cloud", "Messagerie & Apps\nmetier (KYC, OPCVM)", shape="box3d", fillcolor="#BBD8F0")

# -------------------- Cluster 2 : Collecte --------------------
with g.subgraph(name="cluster_collecte") as c:
    c.attr(label="Collecte", style="rounded,filled", fillcolor="#FBF3D9",
           color="#B8942E", fontsize="12")
    c.node("agents", "Agents Wazuh\n(endpoint / syslog)", shape="component", fillcolor="#F5E1A4")

# -------------------- Cluster 3 : SIEM (Wazuh) --------------------
with g.subgraph(name="cluster_siem") as c:
    c.attr(label="SIEM - Wazuh", style="rounded,filled", fillcolor="#E4F5E1",
           color="#3C8B3C", fontsize="12")
    c.node("manager", "Wazuh Manager\n(regles + active-response)", shape="box", fillcolor="#A9DDA4")
    c.node("indexer", "Wazuh Indexer\n(OpenSearch)", shape="cylinder", fillcolor="#A9DDA4")
    c.node("dashboard", "Wazuh Dashboard\n(analyste SOC)", shape="box", fillcolor="#A9DDA4")
    c.edge("manager", "indexer", label="alertes JSON")
    c.edge("indexer", "dashboard", label="visualisation")

# -------------------- Cluster 4 : SOAR --------------------
with g.subgraph(name="cluster_soar") as c:
    c.attr(label="SOAR", style="rounded,filled", fillcolor="#FBE3E3",
           color="#B84A4A", fontsize="12")
    c.node("orchestrator", "Orchestrateur SOAR\n(playbooks Python/Flask)", shape="box", fillcolor="#F3B3B3")
    c.node("cortex", "Cortex\n(enrichissement IOC)", shape="box", fillcolor="#F3B3B3")
    c.node("thehive", "TheHive\n(gestion des cas / IR)", shape="box", fillcolor="#F3B3B3")
    c.edge("orchestrator", "cortex", label="enrichir IP/hash")
    c.edge("orchestrator", "thehive", label="creer cas")

# -------------------- Cluster 5 : Reponse --------------------
with g.subgraph(name="cluster_response") as c:
    c.attr(label="Reponse automatisee", style="rounded,filled", fillcolor="#EDE3FB",
           color="#6E4AB8", fontsize="12")
    c.node("firewall_block", "Blocage IP\n(firewall-drop)", shape="cds", fillcolor="#D3BFF0")
    c.node("disable_acct", "Desactivation\ncompte AD", shape="cds", fillcolor="#D3BFF0")
    c.node("notify", "Notification\nSlack / Email SOC", shape="cds", fillcolor="#D3BFF0")

# -------------------- Analyste --------------------
g.node("analyst", "Analyste SOC\n/ RSSI", shape="ellipse", fillcolor="#FFFFFF", color="#333333")

# -------------------- Liens principaux --------------------
for src in ["ad", "trading", "endpoints", "net", "cloud"]:
    g.edge(src, "agents", color="#888888")

g.edge("agents", "manager", label="logs (1514/TCP, syslog 514/UDP)")
g.edge("manager", "orchestrator", label="webhook alertes\n(niveau >= 7)", color="#B84A4A", fontcolor="#B84A4A")
g.edge("manager", "firewall_block", label="active-response", color="#6E4AB8", fontcolor="#6E4AB8")
g.edge("manager", "disable_acct", label="active-response", color="#6E4AB8", fontcolor="#6E4AB8")
g.edge("orchestrator", "notify", color="#6E4AB8")
g.edge("dashboard", "analyst", dir="both")
g.edge("thehive", "analyst", dir="both", label="investigation IR")
g.edge("notify", "analyst")

g.render("architecture_siem_soar", cleanup=True)
g.format = "svg"
g.render("architecture_siem_soar", cleanup=True)
print("Diagramme genere.")
