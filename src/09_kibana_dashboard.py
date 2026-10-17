"""Create the "SSH Attack Detection - SOC Dashboard" in Kibana through the saved-objects import API.

Panels are Vega-Lite visualizations that query Elasticsearch directly, so the dashboard works
right after 07_elastic_load.py with no manual setup. The time range and histogram bucket size are
read from the loaded data, so the dashboard fits whatever 01_generate_data.py produced.
Re-running overwrites the same objects.
"""
import json
import time
from datetime import datetime, timedelta

import requests
from elasticsearch import Elasticsearch

import config

VL = "https://vega.github.io/schema/vega-lite/v5.json"
KIBANA_VERSION = "8.15.3"
DASHBOARD_ID = "ssh-attack-soc-dashboard"

TYPES = ["benign", "brute_force", "low_and_slow", "password_spraying", "credential_stuffing",
         "user_enumeration", "post_compromise", "unlabelled"]
TYPE_SCALE = {"domain": TYPES, "range": config.COLORS[:7] + [config.MUTED]}
DETECTED = ["Rules + KMeans", "KMeans only", "Rules only", "Graph only", "Not detected"]
DETECTED_SCALE = {"domain": DETECTED, "range": [config.COLORS[6], config.COLORS[1], config.COLORS[0],
                                                config.COLORS[2], "#c3c2b7"]}
TIME_RANGE = {"range": {"@timestamp": {"%timefilter%": True}}}
ANY_FLAG = {"bool": {"should": [{"term": {"rule_flag": True}}, {"term": {"ml_flag": True}},
                                {"term": {"graph_flag": True}}], "minimum_should_match": 1}}


def failed_over_time(interval_h):
    return {
        "$schema": VL,
        "title": "Failed SSH logins over time, by ground-truth attack type",
        "data": {"url": {"index": "auth-events", "body": {
            "size": 0,
            "query": {"bool": {"filter": [{"term": {"event.keyword": "FAILED"}}, TIME_RANGE]}},
            "aggs": {"t": {"date_histogram": {"field": "@timestamp", "fixed_interval": f"{interval_h}h", "min_doc_count": 0},
                           "aggs": {"types": {"terms": {"field": "attack_type.keyword", "size": 10}}}}}}},
                 "format": {"property": "aggregations.t.buckets"}},
        "transform": [{"calculate": "datum.types.buckets", "as": "tb"},
                      {"flatten": ["tb"]},
                      {"calculate": "datum.tb.key", "as": "attack_type"},
                      {"calculate": "datum.tb.doc_count", "as": "failed"},
                      {"calculate": "toDate(datum.key)", "as": "time"}],
        "mark": {"type": "bar", "tooltip": True},
        "encoding": {
            "x": {"field": "time", "type": "temporal", "title": None},
            "y": {"field": "failed", "type": "quantitative", "stack": True, "title": f"Failed logins per {interval_h} h"},
            "color": {"field": "attack_type", "type": "nominal", "scale": TYPE_SCALE, "title": "Attack type"},
            "tooltip": [{"field": "time", "type": "temporal", "format": "%d %b %H:%M"},
                        {"field": "attack_type"}, {"field": "failed", "title": "Failed logins"}]},
    }


def hourly_anomalies():
    return {
        "$schema": VL,
        "title": "Hourly failed logins vs. Holt-Winters baseline (red = anomalous hour)",
        "data": {"url": {"index": "auth-hourly", "body": {
            "size": 5000, "sort": [{"@timestamp": "asc"}], "query": {"bool": {"filter": [TIME_RANGE]}}}},
                 "format": {"property": "hits.hits"}},
        "transform": [{"calculate": "toDate(datum._source['@timestamp'])", "as": "time"},
                      {"calculate": "datum._source.failed", "as": "Failed logins"},
                      {"calculate": "datum._source.expected", "as": "Expected"},
                      {"calculate": "datum._source.anomaly", "as": "anomaly"}],
        "encoding": {"x": {"field": "time", "type": "temporal", "title": None}},
        "layer": [
            {"transform": [{"fold": ["Failed logins", "Expected"], "as": ["series", "value"]}],
             "mark": {"type": "line", "strokeWidth": 1.6, "interpolate": "monotone"},
             "encoding": {"y": {"field": "value", "type": "quantitative", "title": "Failed logins / hour",
                                "scale": {"type": "symlog"}},
                          "color": {"field": "series", "type": "nominal", "title": None,
                                    "scale": {"domain": ["Failed logins", "Expected"],
                                              "range": [config.MUTED, config.COLORS[0]]}}}},
            {"transform": [{"filter": "datum.anomaly === true"}],
             "mark": {"type": "point", "filled": True, "size": 70, "color": config.COLORS[7], "tooltip": True},
             "encoding": {"y": {"field": "Failed logins", "type": "quantitative"},
                          "tooltip": [{"field": "time", "type": "temporal", "format": "%d %b %H:%M"},
                                      {"field": "Failed logins"}, {"field": "Expected", "format": ".1f"}]}},
        ],
    }


def top_ips():
    return {
        "$schema": VL,
        "title": "Top 15 IPs by risk score (SOC triage)",
        "data": {"url": {"index": "auth-ip-risk", "body": {
            "size": 15, "sort": [{"risk_score": "desc"}], "query": ANY_FLAG}},
                 "format": {"property": "hits.hits"}},
        "transform": [{"calculate": "datum._source.ip", "as": "ip"},
                      {"calculate": "datum._source.risk_score", "as": "risk"},
                      {"calculate": "datum._source.predicted_type || 'unlabelled'", "as": "type"},
                      {"calculate": "datum._source.technique_id || '-'", "as": "technique"}],
        "mark": {"type": "bar", "cornerRadiusEnd": 3, "tooltip": True},
        "encoding": {
            "y": {"field": "ip", "type": "nominal", "sort": "-x", "title": None},
            "x": {"field": "risk", "type": "quantitative", "title": "Risk score (0-100)",
                  "scale": {"domain": [0, 100]}},
            "color": {"field": "type", "type": "nominal", "scale": TYPE_SCALE, "title": "Predicted attack"},
            "tooltip": [{"field": "ip"}, {"field": "risk"}, {"field": "type"}, {"field": "technique"}]},
    }


def mitre_donut():
    return {
        "$schema": VL,
        "title": "Flagged IPs by MITRE ATT&CK technique",
        "data": {"url": {"index": "auth-ip-risk", "body": {
            "size": 0, "query": ANY_FLAG,
            "aggs": {"t": {"terms": {"field": "technique_name.keyword", "size": 10,
                                     "missing": "Untyped (graph only)"}}}}},
                 "format": {"property": "aggregations.t.buckets"}},
        "mark": {"type": "arc", "innerRadius": 55, "stroke": "white", "strokeWidth": 2, "tooltip": True},
        "encoding": {
            "theta": {"field": "doc_count", "type": "quantitative"},
            "color": {"field": "key", "type": "nominal", "title": "Technique",
                      "scale": {"range": config.COLORS}},
            "tooltip": [{"field": "key", "title": "Technique"}, {"field": "doc_count", "title": "IPs"}]},
    }


def detection_by_method():
    return {
        "$schema": VL,
        "title": "Which method caught each attack type (attacker IPs only)",
        "data": {"url": {"index": "auth-ip-risk", "body": {
            "size": 0,
            "query": {"bool": {"filter": [{"exists": {"field": "true_type"}}],
                               "must_not": [{"term": {"true_type.keyword": "benign"}}]}},
            "aggs": {"t": {"terms": {"field": "true_type.keyword", "size": 10},
                           "aggs": {"d": {"terms": {"field": "detected_by.keyword", "size": 10}}}}}}},
                 "format": {"property": "aggregations.t.buckets"}},
        "transform": [{"calculate": "datum.d.buckets", "as": "db"},
                      {"flatten": ["db"]},
                      {"calculate": "datum.db.key", "as": "detected_by"},
                      {"calculate": "datum.db.doc_count", "as": "ips"},
                      {"calculate": "replace(datum.key, regexp('_', 'g'), ' ')", "as": "attack"}],
        "mark": {"type": "bar", "tooltip": True},
        "encoding": {
            "x": {"field": "attack", "type": "nominal", "title": None, "axis": {"labelAngle": 0}},
            "y": {"field": "ips", "type": "quantitative", "stack": "normalize", "title": "Share of attacker IPs",
                  "axis": {"format": "%"}},
            "color": {"field": "detected_by", "type": "nominal", "scale": DETECTED_SCALE, "title": "Detected by"},
            "order": {"field": "detected_by"},
            "tooltip": [{"field": "attack"}, {"field": "detected_by"}, {"field": "ips", "title": "IPs"}]},
    }


def panels(interval_h):  # (id, title, spec, x, y, w, h) on Kibana's 48-column grid
    return [
        ("ssh-failed-over-time", "Failed logins over time", failed_over_time(interval_h), 0, 0, 48, 14),
        ("ssh-hourly-anomalies", "Hourly anomalies", hourly_anomalies(), 0, 14, 48, 14),
        ("ssh-top-ips", "Top risk IPs", top_ips(), 0, 28, 26, 18),
        ("ssh-mitre", "MITRE techniques", mitre_donut(), 26, 28, 22, 18),
        ("ssh-detection-method", "Detection method by attack type", detection_by_method(), 0, 46, 48, 16),
    ]
EMPTY_SEARCH = json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})


def data_range():
    """First/last event in auth-events, padded to whole days, and a bucket size giving ~120 bars."""
    es = Elasticsearch(config.ES_URL, request_timeout=60)
    es.indices.refresh(index="auth-events")
    aggs = es.search(index="auth-events", size=0, aggs={"lo": {"min": {"field": "@timestamp"}},
                                                         "hi": {"max": {"field": "@timestamp"}}})["aggregations"]
    lo = datetime.fromisoformat(aggs["lo"]["value_as_string"].replace("Z", "+00:00")).replace(
        hour=0, minute=0, second=0, microsecond=0)
    hi = datetime.fromisoformat(aggs["hi"]["value_as_string"].replace("Z", "+00:00")).replace(
        hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    interval_h = max(1, round((hi - lo).total_seconds() / 3600 / 120))
    return lo, hi, interval_h


def wait_for_kibana(timeout_s=180):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = requests.get(f"{config.KIBANA_URL}/api/status", timeout=10)
            if r.ok and r.json().get("status", {}).get("overall", {}).get("level") == "available":
                return
        except (requests.RequestException, ValueError):
            pass
        print("Waiting for Kibana...")
        time.sleep(5)
    raise SystemExit("Kibana did not become available")


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def saved_objects(time_from, time_to, interval_h):
    objs, panels_json, refs = [], [], []
    for i, (vid, title, spec, x, y, w, h) in enumerate(panels(interval_h)):
        objs.append({"type": "visualization", "id": vid, "references": [], "attributes": {
            "title": title, "description": "", "uiStateJSON": "{}",
            "visState": json.dumps({"title": title, "type": "vega", "aggs": [],
                                    "params": {"spec": json.dumps(spec, indent=2)}}),
            "kibanaSavedObjectMeta": {"searchSourceJSON": EMPTY_SEARCH}}})
        panels_json.append({"version": KIBANA_VERSION, "type": "visualization", "panelIndex": str(i),
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                       "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "visualization", "id": vid})
    objs.append({"type": "dashboard", "id": DASHBOARD_ID, "references": refs, "attributes": {
        "title": "SSH Attack Detection - SOC Dashboard",
        "description": "Kafka + Spark + MLlib + Neo4j pipeline results on SSH authentication logs",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": iso(time_from), "timeTo": iso(time_to),
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": EMPTY_SEARCH}}})
    return objs


def main():
    time_from, time_to, interval_h = data_range()
    print(f"Data spans {time_from:%d %b %Y} - {time_to:%d %b %Y}; histogram bucket {interval_h} h")
    wait_for_kibana()
    ndjson = "\n".join(json.dumps(o) for o in saved_objects(time_from, time_to, interval_h)) + "\n"
    (config.OUT / "kibana_dashboard.ndjson").write_text(ndjson, encoding="utf-8")
    r = requests.post(f"{config.KIBANA_URL}/api/saved_objects/_import?overwrite=true",
                      headers={"kbn-xsrf": "true"}, timeout=60,
                      files={"file": ("dashboard.ndjson", ndjson, "application/ndjson")})
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
    if r.ok and isinstance(body, dict) and body.get("success"):
        print(f"Imported {body.get('successCount')} objects.")
        print(f"Open: http://localhost:5601/app/dashboards#/view/{DASHBOARD_ID}")
    else:
        print(f"Import failed (HTTP {r.status_code}): {json.dumps(body, indent=2)[:3000]}")
        print("You can also import output/kibana_dashboard.ndjson by hand: "
              "Stack Management > Saved objects > Import.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
