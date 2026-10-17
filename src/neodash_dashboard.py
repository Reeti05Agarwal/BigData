"""NeoDash dashboard for the attack graph, stored inside Neo4j so NeoDash opens it automatically.

Every report is a live Cypher query with no hard-coded IPs or community ids, so the panels
always reflect the graph that 06_neo4j_graph.py just loaded.
"""
import json
import uuid

TITLE = "SSH Attack Graph - Campaign Analysis"
FLAGGED = "(i.rule_flag OR i.ml_flag OR i.graph_flag)"


def report(title, query, rtype, x, y, w, h, selection=None, settings=None):
    return {"id": str(uuid.uuid5(uuid.NAMESPACE_URL, title)), "title": title, "query": query.strip(),
            "type": rtype, "x": x, "y": y, "width": w, "height": h,
            "selection": selection or {}, "settings": settings or {}, "schema": []}


GRAPH_SEL = {"IP": "ip", "User": "name", "Host": "name"}
GRAPH_SET = {"nodeColorProp": "color", "defaultNodeSize": 3, "relationshipParticles": False}

OVERVIEW = [
    report("Flagged attacker IPs", f"MATCH (i:IP) WHERE {FLAGGED} RETURN count(i)", "value", 0, 0, 6, 2),
    report("Coordinated campaigns (>= 3 attacker IPs)", f"""
        MATCH (i:IP) WHERE {FLAGGED}
        WITH i.community AS c, count(*) AS n WHERE n >= 3
        RETURN count(c)""", "value", 6, 0, 6, 2),
    report("Accounts targeted by attackers", f"""
        MATCH (i:IP)-[:ATTEMPTED]->(u:User) WHERE {FLAGGED}
        RETURN count(DISTINCT u)""", "value", 12, 0, 6, 2),
    report("Found only by graph analysis", "MATCH (i:IP) WHERE i.graph_flag RETURN count(i)", "value", 18, 0, 6, 2),
    report("Attacker IPs per campaign community", f"""
        MATCH (i:IP) WHERE {FLAGGED}
        WITH i.community AS c, count(*) AS ips, collect(DISTINCT coalesce(i.predicted_type, 'graph only')) AS stages
        WHERE ips >= 3
        RETURN 'C' + toString(c) + ' ' + reduce(s = '', t IN stages | s + left(t, 5) + ' ') AS community, ips
        ORDER BY ips DESC LIMIT 10""", "bar", 0, 2, 12, 4,
           {"index": "community", "value": "ips", "key": "(none)"}),
    report("Flagged IPs by MITRE ATT&CK technique", f"""
        MATCH (i:IP) WHERE {FLAGGED}
        RETURN coalesce(i.technique_id, 'graph only') AS technique, count(*) AS ips ORDER BY ips DESC""",
           "pie", 12, 2, 12, 4, {"index": "technique", "value": "ips", "key": "(none)"}),
    report("Multi-stage links: attacker communities sharing target accounts", f"""
        MATCH (a:IP)-[:ATTEMPTED]->(u:User)<-[:ATTEMPTED]-(b:IP)
        WHERE a.community < b.community AND {FLAGGED.replace('i.', 'a.')} AND {FLAGGED.replace('i.', 'b.')}
        WITH a.community AS community_a, b.community AS community_b, count(DISTINCT u) AS shared_accounts,
             collect(DISTINCT a.predicted_type) AS stages_a, collect(DISTINCT b.predicted_type) AS stages_b
        WHERE shared_accounts >= 5
        RETURN community_a, stages_a, community_b, stages_b, shared_accounts ORDER BY shared_accounts DESC""",
           "table", 0, 6, 12, 4),
    report("Most central attacker IPs (PageRank)", f"""
        MATCH (i:IP) WHERE {FLAGGED}
        RETURN i.ip AS ip, round(i.pagerank, 3) AS pagerank, i.community AS community,
               coalesce(i.predicted_type, 'graph only') AS attack, i.risk_score AS risk
        ORDER BY i.pagerank DESC LIMIT 10""", "table", 12, 6, 12, 4),
]

GRAPHS = [
    report("Largest multi-stage campaign (two linked communities and their target accounts)", f"""
        MATCH (a:IP)-[:ATTEMPTED]->(u:User)<-[:ATTEMPTED]-(b:IP)
        WHERE a.community < b.community AND {FLAGGED.replace('i.', 'a.')} AND {FLAGGED.replace('i.', 'b.')}
        WITH a.community AS ca, b.community AS cb, count(DISTINCT u) AS shared
        ORDER BY shared DESC LIMIT 1
        MATCH (i:IP)-[r:ATTEMPTED]->(u:User)
        WHERE i.community IN [ca, cb] AND {FLAGGED}
        RETURN i, r, u LIMIT 500""", "graph", 0, 0, 24, 6, GRAPH_SEL, GRAPH_SET),
    report("Largest campaign community", f"""
        MATCH (i:IP) WHERE {FLAGGED}
        WITH i.community AS c, count(*) AS n ORDER BY n DESC LIMIT 1
        MATCH (i:IP {{community: c}})-[r:ATTEMPTED]->(u:User) WHERE {FLAGGED}
        RETURN i, r, u LIMIT 400""", "graph", 0, 6, 12, 5, GRAPH_SEL, GRAPH_SET),
    report("Lateral movement: attacker IPs logging in to several hosts", f"""
        MATCH (i:IP)-[t:TARGETED]->(h:Host)
        WHERE t.success > 0 AND {FLAGGED}
          AND COUNT {{ (i)-[t2:TARGETED]->() WHERE t2.success > 0 }} > 1
        RETURN i, t, h""", "graph", 12, 6, 12, 5, GRAPH_SEL, GRAPH_SET),
    report("Most attacked accounts and the IPs hitting them", f"""
        MATCH (u:User)<-[:ATTEMPTED]-(i:IP) WHERE {FLAGGED}
        WITH u, count(i) AS n ORDER BY n DESC LIMIT 5
        MATCH (u)<-[r:ATTEMPTED]-(i:IP) WHERE {FLAGGED}
        RETURN u, r, i LIMIT 300""", "graph", 0, 11, 24, 5, GRAPH_SEL, GRAPH_SET),
]

QUALITY = [
    report("Detection method by ground-truth attack type", """
        MATCH (i:IP) WHERE i.true_type IS NOT NULL AND i.true_type <> 'benign'
        RETURN i.true_type AS attack, i.detected_by AS method, count(*) AS ips
        ORDER BY attack""", "bar", 0, 0, 24, 5,
           {"index": "attack", "value": "ips", "key": "method"}, {"groupMode": "stacked"}),
    report("Benign IPs flagged (false positives) and why", f"""
        MATCH (i:IP) WHERE i.true_type = 'benign' AND {FLAGGED}
        RETURN i.ip AS ip, i.detected_by AS detected_by, i.predicted_type AS profiled_as,
               i.n_events AS events, i.risk_score AS risk ORDER BY risk DESC""", "table", 0, 5, 12, 4),
    report("Attacker IPs still missed", """
        MATCH (i:IP) WHERE i.true_type IS NOT NULL AND i.true_type <> 'benign' AND i.detected_by = 'Not detected'
        RETURN i.ip AS ip, i.true_type AS attack, i.community AS community, i.n_events AS events""",
           "table", 12, 5, 12, 4),
]


def dashboard():
    return {
        "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, TITLE)), "title": TITLE, "version": "2.4",
        "settings": {"pagenumber": 0, "editable": True, "fullscreenEnabled": True, "parameters": {},
                     "theme": "light"},
        "pages": [{"title": "Campaign overview", "reports": OVERVIEW},
                  {"title": "Attack graphs", "reports": GRAPHS},
                  {"title": "Detection quality", "reports": QUALITY}],
        "parameters": {}, "extensions": {"active": True, "activeReducers": []},
    }


def save_dashboard(session):
    """NeoDash lists dashboards stored as (:_Neodash_Dashboard) nodes and can auto-load one by title."""
    d = dashboard()
    session.run("""
        MERGE (n:_Neodash_Dashboard {title: $title})
        SET n.uuid = $uuid, n.version = '2.4', n.user = 'neo4j', n.date = datetime(), n.content = $content""",
                title=d["title"], uuid=d["uuid"], content=json.dumps(d)).consume()
