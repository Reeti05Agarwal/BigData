"""Load the attack graph into Neo4j, run Louvain + PageRank (GDS), and export campaigns.

Graph-assisted detection: an IP that rules and KMeans missed is flagged when it sits in a
campaign community (>= 3 flagged IPs) and behaves like an attacker there (mostly failures
against >= 3 accounts). This recovers bots that spread attempts too thin for per-IP
analysis, such as a password-spraying botnet.

Graph model
  (:IP {ip, risk_score, predicted_type, technique_id, rule_flag, ml_flag})
  (:User {name})   (:Host {name})
  (:IP)-[:ATTEMPTED {attempts, failed, success}]->(:User)
  (:IP)-[:TARGETED  {attempts, success}]->(:Host)
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
import pandas as pd
from neo4j import GraphDatabase

import config
from plots import ATTACK_ORDER, style

BATCH = 5000


def batched(session, query, rows):
    for i in range(0, len(rows), BATCH):
        session.run(query, rows=rows[i:i + BATCH]).consume()


def main():
    ips = pd.read_csv(config.OUT / "ip_risk.csv")
    ips = ips[["ip", "risk_score", "predicted_type", "technique_id", "rule_flag", "ml_flag", "n_events",
               "distinct_users", "cluster"]]
    ips = ips.astype(object).where(ips.notna(), None)
    eu = pd.read_csv(config.OUT / "edges_ip_user.csv").fillna({"user": ""})
    eh = pd.read_csv(config.OUT / "edges_ip_host.csv")

    driver = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    with driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n").consume()
        for q in ["CREATE CONSTRAINT ip_key IF NOT EXISTS FOR (n:IP) REQUIRE n.ip IS UNIQUE",
                  "CREATE CONSTRAINT user_key IF NOT EXISTS FOR (n:User) REQUIRE n.name IS UNIQUE",
                  "CREATE CONSTRAINT host_key IF NOT EXISTS FOR (n:Host) REQUIRE n.name IS UNIQUE"]:
            s.run(q).consume()
        batched(s, "UNWIND $rows AS r MERGE (i:IP {ip: r.ip}) SET i += r", ips.to_dict("records"))
        batched(s, """UNWIND $rows AS r
                      MATCH (i:IP {ip: r.ip}) MERGE (u:User {name: r.user})
                      MERGE (i)-[e:ATTEMPTED]->(u)
                      SET e.attempts = r.attempts, e.failed = r.failed, e.success = r.success""",
                eu.to_dict("records"))
        batched(s, """UNWIND $rows AS r
                      MATCH (i:IP {ip: r.ip}) MERGE (h:Host {name: r.host})
                      MERGE (i)-[e:TARGETED]->(h) SET e.attempts = r.attempts, e.success = r.success""",
                eh.to_dict("records"))
        print(f"Loaded {len(ips):,} IPs, {len(eu):,} IP-User edges, {len(eh):,} IP-Host edges")

        # Community detection over the IP-User bipartite graph: IPs sharing target accounts cluster together
        s.run("CALL gds.graph.drop('auth', false) YIELD graphName").consume()
        s.run("""CALL gds.graph.project('auth', ['IP', 'User'],
                   {ATTEMPTED: {orientation: 'UNDIRECTED'}})""").consume()
        louvain = s.run("CALL gds.louvain.write('auth', {writeProperty: 'community'}) "
                        "YIELD communityCount, modularity").single()
        s.run("CALL gds.pageRank.write('auth', {writeProperty: 'pagerank'}) YIELD nodePropertiesWritten").consume()
        s.run("CALL gds.graph.drop('auth') YIELD graphName").consume()
        print(f"Louvain: {louvain['communityCount']} communities, modularity {louvain['modularity']:.3f}")

        s.run("MATCH (i:IP) SET i.graph_flag = false").consume()
        graph_hits = s.run("""
            MATCH (i:IP) WHERE i.rule_flag OR i.ml_flag
            WITH i.community AS c, count(*) AS n WHERE n >= 3
            WITH collect(c) AS campaign_communities
            MATCH (x:IP)-[a:ATTEMPTED]->(u:User)
            WHERE x.community IN campaign_communities AND NOT (x.rule_flag OR x.ml_flag)
            WITH x, count(DISTINCT u) AS users, sum(a.failed) AS failed, sum(a.success) AS success
            WHERE users >= 3 AND failed > 2 * success
            SET x.graph_flag = true
            RETURN x.ip AS ip, x.community AS community, users, failed""").data()
        print(f"Graph-assisted detection flagged {len(graph_hits)} IPs missed by rules and KMeans")

        campaigns = s.run("""
            MATCH (i:IP) WHERE i.rule_flag OR i.ml_flag OR i.graph_flag
            WITH i.community AS community, collect(i) AS ips
            WHERE size(ips) >= 3
            MATCH (x:IP)-[:ATTEMPTED]->(u:User) WHERE x IN ips
            WITH community, ips, count(DISTINCT u) AS targeted_users,
                 collect(DISTINCT x.predicted_type) AS stages
            RETURN community, size(ips) AS attacker_ips, targeted_users, stages,
                   [n IN ips | n.ip][..10] AS sample_ips,
                   round(reduce(r = 0.0, n IN ips | r + n.risk_score) / size(ips), 1) AS avg_risk
            ORDER BY attacker_ips DESC""").data()
        # Multi-stage links: attacker communities that hit the same accounts (e.g. scanners -> sprayers)
        links = s.run("""
            MATCH (a:IP)-[:ATTEMPTED]->(u:User)<-[:ATTEMPTED]-(b:IP)
            WHERE a.community < b.community
              AND (a.rule_flag OR a.ml_flag OR a.graph_flag) AND (b.rule_flag OR b.ml_flag OR b.graph_flag)
            WITH a.community AS community_a, b.community AS community_b, count(DISTINCT u) AS shared_users,
                 collect(DISTINCT a.predicted_type) AS stages_a, collect(DISTINCT b.predicted_type) AS stages_b
            WHERE shared_users >= 5
            RETURN community_a, stages_a, community_b, stages_b, shared_users
            ORDER BY shared_users DESC""").data()
        central = s.run("""
            MATCH (i:IP) WHERE i.rule_flag OR i.ml_flag
            RETURN i.ip AS ip, round(i.pagerank, 4) AS pagerank, i.community AS community,
                   i.predicted_type AS predicted_type, i.risk_score AS risk_score
            ORDER BY i.pagerank DESC LIMIT 15""").data()
        communities = s.run("MATCH (i:IP) RETURN i.ip AS ip, i.community AS community, "
                            "i.pagerank AS pagerank, i.graph_flag AS graph_flag").data()
    driver.close()

    camp = pd.DataFrame(campaigns)
    camp.to_csv(config.OUT / "campaigns.csv", index=False)
    pd.DataFrame(central).to_csv(config.OUT / "central_ips.csv", index=False)
    comm = pd.DataFrame(communities)
    comm.to_csv(config.OUT / "ip_communities.csv", index=False)
    pd.DataFrame(graph_hits).to_csv(config.OUT / "graph_detections.csv", index=False)
    pd.DataFrame(links).to_csv(config.OUT / "linked_campaigns.csv", index=False)

    # Campaign purity against ground truth: are the injected campaigns recovered as one community?
    labels = pd.read_csv(config.LABELS_CSV)
    lab = labels[labels["label"] == "attack"].merge(comm, on="ip")
    purity = (lab.groupby("campaign")["community"]
              .agg(ips="count", communities="nunique",
                   largest_share=lambda c: c.value_counts().iloc[0] / len(c)).reset_index())
    purity.to_csv(config.OUT / "campaign_recovery.csv", index=False)

    print("\nCoordinated campaigns (communities with >= 3 flagged IPs):")
    print(camp.drop(columns=["sample_ips"]).to_string(index=False) if len(camp) else "none")
    print("\nMost central attacker IPs (PageRank):")
    print(pd.DataFrame(central).to_string(index=False))
    print("\nGround-truth campaign recovery:")
    print(purity.to_string(index=False))
    print("\nLinked attacker communities (multi-stage, >= 5 shared accounts):")
    print(pd.DataFrame(links).to_string(index=False) if links else "none")
    evaluate_with_graph(comm, labels)


def evaluate_with_graph(comm, labels):
    """Add graph-assisted detection to the rules vs. KMeans comparison."""
    res = pd.read_csv(config.OUT / "ip_risk.csv")[["ip", "rule_flag", "ml_flag"]].merge(comm, on="ip")
    ev = res.merge(labels, on="ip")
    ev["graph_flag"] = ev["graph_flag"].fillna(False).astype(bool)
    ev["ml_graph"] = ev["ml_flag"] | ev["graph_flag"]
    ev["all_flag"] = ev["rule_flag"] | ev["ml_graph"]
    y = ev["label"] == "attack"
    rows = []
    for name, col in [("Threshold rules", "rule_flag"), ("KMeans (MLlib)", "ml_flag"),
                      ("KMeans + graph", "ml_graph"), ("Rules + KMeans + graph", "all_flag")]:
        p = ev[col].astype(bool)
        tp, fp, fn = int((p & y).sum()), int((p & ~y).sum()), int((~p & y).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        rows.append({"method": name, "tp": tp, "fp": fp, "fn": fn, "precision": round(prec, 3),
                     "recall": round(rec, 3), "f1": round(f1, 3)})
    metrics = pd.DataFrame(rows)
    metrics.to_csv(config.OUT / "metrics_with_graph.csv", index=False)
    per_type = (ev[y].groupby("attack_type")[["rule_flag", "ml_flag", "ml_graph"]].mean()
                .reindex(ATTACK_ORDER).dropna(how="all"))
    per_type.to_csv(config.OUT / "per_type_detection_with_graph.csv")
    print("\nRules vs. KMeans vs. KMeans + graph on labelled IPs:")
    print(metrics.to_string(index=False))
    print("\nDetection rate by attack type:")
    print(per_type.round(2).to_string())

    fig, ax = plt.subplots(figsize=(9.5, 4.5))
    w = 0.27
    for i, (col, name) in enumerate([("rule_flag", "Threshold rules"), ("ml_flag", "KMeans (MLlib)"),
                                     ("ml_graph", "KMeans + Neo4j graph")]):
        xs = [x + (i - 1) * w for x in range(len(per_type))]
        bars = ax.bar(xs, per_type[col], w - 0.02, color=config.COLORS[i], label=name)
        ax.bar_label(bars, labels=[f"{v:.0%}" for v in per_type[col]], fontsize=7, padding=2)
    ax.set_xticks(range(len(per_type)), [t.replace("_", "\n") for t in per_type.index], fontsize=8)
    ax.set_ylim(0, 1.15)
    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    style(ax, "Attacker IPs detected by attack type: graph analysis recovers distributed bots", ylabel="Detected")
    ax.legend(frameon=False, fontsize=8, loc="upper right", ncol=3)
    fig.savefig(config.FIG / "detection_with_graph.png", dpi=150, bbox_inches="tight")


if __name__ == "__main__":
    main()
