"""Batch analytics: parse -> Parquet -> features -> rules vs. KMeans -> MITRE tags -> metrics + figures.

Outputs in output/:
  ip_risk.csv           one row per IP: features, rule/ML flags, attack type, MITRE technique, risk score
  detections.csv        flagged IPs only, sorted by risk (SOC triage list)
  metrics.csv           precision / recall / F1 for rules vs. KMeans on labelled IPs
  per_type_detection.csv  detection rate per attack type (which attacks rules miss)
  cluster_profile.csv   KMeans cluster centroids in plain terms
  hourly.csv            hourly failed / success counts (input to the forecast)
  edges_ip_user.csv, edges_ip_host.csv  graph edges for Neo4j
  figures/*.png
"""
import json
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from pyspark.sql import functions as F

import config
from pipeline import (get_spark, ip_features, ip_rule_hits, ml_detect, mitre_columns, parse_lines,
                      profile_type, window_aggregates, with_flags)
from plots import ATTACK_ORDER, style, type_color

def evaluate(res, labels):
    ev = res.merge(labels, on="ip", how="inner")
    y = ev["label"] == "attack"
    ev["combined_flag"] = ev["rule_flag"] | ev["ml_flag"]
    rows = []
    for name, col in [("Threshold rules", "rule_flag"), ("KMeans (MLlib)", "ml_flag"),
                      ("Rules OR KMeans", "combined_flag")]:
        p = ev[col].astype(bool)
        tp, fp, fn = int((p & y).sum()), int((p & ~y).sum()), int((~p & y).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        rows.append({"method": name, "tp": tp, "fp": fp, "fn": fn, "precision": round(prec, 3),
                     "recall": round(rec, 3), "f1": round(f1, 3)})
    metrics = pd.DataFrame(rows)

    att = ev[y]
    per_type = att.groupby("attack_type").agg(
        ips=("ip", "count"),
        rules_detected=("rule_flag", "mean"),
        kmeans_detected=("ml_flag", "mean"),
        type_correct=("predicted_type", lambda s: (s == att.loc[s.index, "attack_type"]).mean()),
    ).reindex(ATTACK_ORDER).reset_index()
    return metrics, per_type, ev


def figures(res, ev, metrics, per_type, hourly, info):
    config.FIG.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "figure.dpi": 150, "savefig.bbox": "tight"})

    # 1. PCA projection of every IP, coloured by ground truth for labelled IPs
    fig, ax = plt.subplots(figsize=(8, 6))
    unl = res[~res["ip"].isin(ev["ip"])]
    if len(unl):
        ax.scatter(unl["pca_x"], unl["pca_y"], s=10, c="#c3c2b7", label="Unlabelled (real log)", alpha=0.6)
    groups = ["benign"] + ATTACK_ORDER
    for g in groups:
        d = ev[ev["attack_type"] == g]
        ax.scatter(d["pca_x"], d["pca_y"], s=18 if g == "benign" else 34, c=type_color(g),
                   label=g.replace("_", " "), edgecolors="white", linewidths=0.6,
                   alpha=0.55 if g == "benign" else 0.95)
    var = info["explained_variance"]
    style(ax, "PCA of per-IP behaviour: attackers separate from normal users",
          f"PC1 ({var[0]:.0%} variance)", f"PC2 ({var[1]:.0%} variance)")
    ax.grid(axis="both", color=config.GRID, linewidth=0.6)
    ax.legend(frameon=False, fontsize=8, loc="best")
    fig.savefig(config.FIG / "pca_scatter.png")
    plt.close(fig)

    # 2. Precision / recall / F1, rules vs. KMeans
    fig, ax = plt.subplots(figsize=(8, 4.5))
    m = metrics.set_index("method")[["precision", "recall", "f1"]]
    width = 0.26
    for i, method in enumerate(m.index):
        xs = [j + (i - 1) * width for j in range(3)]
        bars = ax.bar(xs, m.loc[method], width - 0.02, color=config.COLORS[i], label=method)
        ax.bar_label(bars, fmt="%.2f", fontsize=8, color=config.INK, padding=2)
    ax.set_xticks(range(3), ["Precision", "Recall", "F1"])
    ax.set_ylim(0, 1.12)
    style(ax, "Detection quality on labelled IPs", ylabel="Score")
    ax.legend(frameon=False, fontsize=8, ncol=3, loc="upper left")
    fig.savefig(config.FIG / "metrics_comparison.png")
    plt.close(fig)

    # 3. Which attacks rules miss
    fig, ax = plt.subplots(figsize=(9, 4.5))
    pt = per_type.dropna(subset=["ips"])
    xs = range(len(pt))
    b1 = ax.bar([x - 0.2 for x in xs], pt["rules_detected"], 0.38, color=config.COLORS[0], label="Threshold rules")
    b2 = ax.bar([x + 0.2 for x in xs], pt["kmeans_detected"], 0.38, color=config.COLORS[1], label="KMeans (MLlib)")
    ax.bar_label(b1, labels=[f"{v:.0%}" for v in pt["rules_detected"]], fontsize=8, padding=2)
    ax.bar_label(b2, labels=[f"{v:.0%}" for v in pt["kmeans_detected"]], fontsize=8, padding=2)
    ax.set_xticks(list(xs), [t.replace("_", "\n") for t in pt["attack_type"]], fontsize=8)
    ax.set_ylim(0, 1.15)
    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    style(ax, "Share of attacker IPs detected, by attack type", ylabel="Detected")
    ax.legend(frameon=False, fontsize=8, loc="upper right")
    fig.savefig(config.FIG / "detection_by_attack_type.png")
    plt.close(fig)

    # 4. Top 15 IPs by risk score
    top = res[res["risk_score"] > 0].nlargest(15, "risk_score").iloc[::-1]
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(top["ip"], top["risk_score"], color=[type_color(t) for t in top["predicted_type"]], height=0.7)
    for t in dict.fromkeys(top["predicted_type"].iloc[::-1]):
        ax.barh([], [], color=type_color(t), label=str(t).replace("_", " "))
    style(ax, "Top 15 IPs by risk score (SOC triage)", "Risk score (0-100)")
    ax.grid(axis="x", color=config.GRID, linewidth=0.6)
    ax.grid(axis="y", visible=False)
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    fig.savefig(config.FIG / "top_risk_ips.png")
    plt.close(fig)

    # 5. Hourly authentication volume
    fig, ax = plt.subplots(figsize=(11, 4))
    ax.plot(hourly["hour"], hourly["failed"], color=config.COLORS[1], linewidth=1.2, label="Failed")
    ax.plot(hourly["hour"], hourly["success"], color=config.COLORS[0], linewidth=1.2, label="Successful")
    style(ax, "Hourly SSH authentication events", ylabel="Events per hour")
    ax.legend(frameon=False, fontsize=8)
    fig.savefig(config.FIG / "hourly_volume.png")
    plt.close(fig)

    # 6. Silhouette by k
    fig, ax = plt.subplots(figsize=(6, 3.5))
    ks, ss = zip(*info["k_scores"])
    ax.plot(ks, ss, color=config.COLORS[0], linewidth=2, marker="o", markersize=7)
    ax.axvline(info["k"], color=config.MUTED, linestyle="--", linewidth=1)
    style(ax, f"KMeans model selection (chosen k = {info['k']})", "k (clusters)", "Silhouette score")
    fig.savefig(config.FIG / "kmeans_silhouette.png")
    plt.close(fig)


def main():
    config.OUT.mkdir(parents=True, exist_ok=True)
    spark = get_spark("auth-batch-analytics")
    timings = {}

    t = time.time()
    raw = spark.read.text(str(config.RAW_LOG))
    parse_lines(raw).write.mode("overwrite").partitionBy("date").parquet(str(config.EVENTS_PARQUET))
    timings["parse_to_parquet_s"] = time.time() - t

    t = time.time()
    events = with_flags(spark.read.parquet(str(config.EVENTS_PARQUET))).cache()
    n_events = events.count()
    win = window_aggregates(events).cache()
    rules = ip_rule_hits(win)
    feats = ip_features(events, win)
    feats = (feats.join(rules, "ip", "left")
             .fillna({"rule_flag": False, "rule_windows": 0}))
    timings["features_rules_s"] = time.time() - t

    t = time.time()
    scored, info = ml_detect(feats)
    timings["kmeans_pca_s"] = time.time() - t

    # Attack type: behavioural profile for anything ML flagged, else the rule that fired
    predicted = F.when(F.col("ml_flag"), profile_type()).otherwise(F.col("rule_type"))
    scored = scored.withColumn("predicted_type", predicted)
    tid, tname = mitre_columns("predicted_type")
    scored = (scored.withColumn("technique_id", tid).withColumn("technique_name", tname)
              .withColumn("risk_score", F.round(
                  25 * F.col("rule_flag").cast("int") + 25 * F.col("ml_flag").cast("int")
                  + F.when(F.col("rule_flag") | F.col("ml_flag"),
                           20 * F.col("fail_ratio")
                           + 15 * F.least(F.lit(1.0), F.col("distinct_users") / 20)
                           + 15 * F.col("success_after_fails").cast("int")).otherwise(0), 1)))

    res = scored.toPandas()
    res["first_seen"] = res["first_seen"].astype(str)
    res["last_seen"] = res["last_seen"].astype(str)
    res = res.sort_values("risk_score", ascending=False)
    res.to_csv(config.OUT / "ip_risk.csv", index=False)
    det_cols = ["ip", "risk_score", "predicted_type", "technique_id", "technique_name", "rule_flag", "ml_flag",
                "rule_type", "cluster", "n_events", "n_failed", "distinct_users", "max_fails_5min",
                "success_after_fails", "first_seen", "last_seen"]
    res[res["rule_flag"] | res["ml_flag"]][det_cols].to_csv(config.OUT / "detections.csv", index=False)
    info["profile"].sort_values("cluster").to_csv(config.OUT / "cluster_profile.csv", index=False)

    hourly = (events.groupBy(F.date_trunc("hour", "ts").alias("hour"))
              .agg(F.sum("is_failed").alias("failed"), F.sum("is_success").alias("success"),
                   F.sum("is_probe").alias("invalid_probes"))
              .orderBy("hour").toPandas())
    hourly.to_csv(config.OUT / "hourly.csv", index=False)

    (events.groupBy("ip", "user").agg(F.sum("is_failed").alias("failed"), F.sum("is_success").alias("success"),
                                      F.count("*").alias("attempts"))
     .toPandas().to_csv(config.OUT / "edges_ip_user.csv", index=False))
    (events.groupBy("ip", "host").agg(F.count("*").alias("attempts"), F.sum("is_success").alias("success"))
     .toPandas().to_csv(config.OUT / "edges_ip_host.csv", index=False))

    labels = pd.read_csv(config.LABELS_CSV)
    metrics, per_type, ev = evaluate(res, labels)
    metrics.to_csv(config.OUT / "metrics.csv", index=False)
    per_type.to_csv(config.OUT / "per_type_detection.csv", index=False)
    figures(res, ev, metrics, per_type, hourly, info)

    summary = {"events": n_events, "ips": len(res), "flagged_ips": int((res["rule_flag"] | res["ml_flag"]).sum()),
               "kmeans_k": info["k"], "silhouette": round(info["silhouette"], 3),
               "pca_explained_variance": [round(v, 3) for v in info["explained_variance"]],
               "timings_s": {k: round(v, 2) for k, v in timings.items()}}
    (config.OUT / "summary.json").write_text(json.dumps(summary, indent=2))

    print(json.dumps(summary, indent=2))
    print("\nRules vs. ML on labelled IPs:\n", metrics.to_string(index=False))
    print("\nDetection rate by attack type:\n", per_type.to_string(index=False))
    print("\nKMeans cluster profile:\n", info["profile"].sort_values("cluster").to_string(index=False))
    spark.stop()


if __name__ == "__main__":
    main()
