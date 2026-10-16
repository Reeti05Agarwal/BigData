"""Load the attack graph into Neo4j, run Louvain + PageRank (GDS), and export campaigns.

Graph model
  (:IP {ip, risk_score, predicted_type, technique_id, rule_flag, ml_flag})
  (:User {name})   (:Host {name})
  (:IP)-[:ATTEMPTED {attempts, failed, success}]->(:User)
  (:IP)-[:TARGETED  {attempts, success}]->(:Host)
"""
import pandas as pd
from neo4j import GraphDatabase

import config

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
        s.run("CALL gds.graph.drop('auth')").consume()
        print(f"Louvain: {louvain['communityCount']} communities, modularity {louvain['modularity']:.3f}")

        campaigns = s.run("""
            MATCH (i:IP) WHERE i.rule_flag OR i.ml_flag
            WITH i.community AS community, collect(i) AS ips
            WHERE size(ips) >= 3
            MATCH (x:IP)-[:ATTEMPTED]->(u:User) WHERE x IN ips
            WITH community, ips, count(DISTINCT u) AS targeted_users,
                 collect(DISTINCT x.predicted_type) AS stages
            RETURN community, size(ips) AS attacker_ips, targeted_users, stages,
                   [n IN ips | n.ip][..10] AS sample_ips,
                   round(reduce(r = 0.0, n IN ips | r + n.risk_score) / size(ips), 1) AS avg_risk
            ORDER BY attacker_ips DESC""").data()
        central = s.run("""
            MATCH (i:IP) WHERE i.rule_flag OR i.ml_flag
            RETURN i.ip AS ip, round(i.pagerank, 4) AS pagerank, i.community AS community,
                   i.predicted_type AS predicted_type, i.risk_score AS risk_score
            ORDER BY i.pagerank DESC LIMIT 15""").data()
        communities = s.run("MATCH (i:IP) RETURN i.ip AS ip, i.community AS community, "
                            "i.pagerank AS pagerank").data()
    driver.close()

    camp = pd.DataFrame(campaigns)
    camp.to_csv(config.OUT / "campaigns.csv", index=False)
    pd.DataFrame(central).to_csv(config.OUT / "central_ips.csv", index=False)
    comm = pd.DataFrame(communities)
    comm.to_csv(config.OUT / "ip_communities.csv", index=False)

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


if __name__ == "__main__":
    main()
