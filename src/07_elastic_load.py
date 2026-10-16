"""Index batch results into Elasticsearch and create Kibana data views for the SOC dashboard.

Indices
  auth-events      every parsed auth event (from the Parquet data lake), with ground-truth attack type
  auth-ip-risk     one doc per IP: risk score, MITRE technique, rule/ML flags, Louvain community
  auth-hourly      hourly failed logins, Holt-Winters baseline and anomaly flag
"""
import argparse

import pandas as pd
import pyarrow.dataset as ds
import requests
from elasticsearch import Elasticsearch, helpers

import config

DATA_VIEWS = {"auth-events": "@timestamp", "auth-ip-risk": "last_seen", "auth-hourly": "@timestamp",
              "auth-stream-alerts": "@timestamp", "auth-stream-events": "@timestamp"}


def bulk(es, index, df, id_col=None):
    if es.indices.exists(index=index):
        es.indices.delete(index=index)
    df = df.astype(object).where(df.notna(), None)
    actions = ({"_index": index, "_source": r, **({"_id": r[id_col]} if id_col else {})}
               for r in df.to_dict("records"))
    ok, _ = helpers.bulk(es.options(request_timeout=120), actions, chunk_size=5000)
    print(f"{index}: {ok:,} docs")


def create_data_views():
    for name, time_field in DATA_VIEWS.items():
        r = requests.post(f"{config.KIBANA_URL}/api/data_views/data_view",
                          headers={"kbn-xsrf": "true"}, timeout=30,
                          json={"data_view": {"title": name, "name": name, "timeFieldName": time_field},
                                "override": True})
        print(f"Kibana data view {name}: HTTP {r.status_code}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--max-events", type=int, default=2_000_000, help="cap on raw events indexed")
    args = ap.parse_args()

    es = Elasticsearch(config.ES_URL, request_timeout=120)
    labels = pd.read_csv(config.LABELS_CSV)[["ip", "attack_type", "campaign"]]

    events = ds.dataset(str(config.EVENTS_PARQUET), format="parquet", partitioning="hive") \
        .head(args.max_events).to_pandas()
    events = events.merge(labels, on="ip", how="left").fillna({"attack_type": "unlabelled", "campaign": ""})
    events["@timestamp"] = pd.to_datetime(events.pop("ts")).dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    events = events.drop(columns=["date"], errors="ignore")
    bulk(es, "auth-events", events)

    risk = pd.read_csv(config.OUT / "ip_risk.csv").drop(columns=["pca_x", "pca_y"], errors="ignore")
    comm_path = config.OUT / "ip_communities.csv"
    if comm_path.exists():
        risk = risk.merge(pd.read_csv(comm_path), on="ip", how="left")
    risk = risk.merge(labels, on="ip", how="left").rename(columns={"attack_type": "true_type"})
    for col in ("first_seen", "last_seen"):
        risk[col] = pd.to_datetime(risk[col]).dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    bulk(es, "auth-ip-risk", risk, id_col="ip")

    fc = config.OUT / "hourly_forecast.csv"
    hourly = pd.read_csv(fc if fc.exists() else config.OUT / "hourly.csv")
    hourly["@timestamp"] = pd.to_datetime(hourly.pop("hour")).dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    bulk(es, "auth-hourly", hourly)

    try:
        create_data_views()
    except requests.RequestException as exc:
        print(f"Kibana not reachable ({exc}); create the data views by hand")
    print("Open Kibana at http://localhost:5601 and set the time range to Sep 2026.")


if __name__ == "__main__":
    main()
