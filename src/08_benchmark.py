"""Scalability benchmark: run parse -> features -> rules -> KMeans at 1x, 5x and 10x data volume."""
import argparse
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from pyspark.sql import functions as F

import config
from plots import style
from pipeline import get_spark, ip_features, ip_rule_hits, ml_detect, parse_lines, window_aggregates, with_flags


def run_once(spark, scale):
    raw = spark.read.text(str(config.RAW_LOG))
    if scale > 1:
        # replicate every line `scale` times: same IPs, `scale` times the event volume
        raw = raw.crossJoin(spark.range(scale).withColumnRenamed("id", "copy")).drop("copy")
    raw = raw.repartition(spark.sparkContext.defaultParallelism * 2)

    t0 = time.time()
    events = with_flags(parse_lines(raw)).cache()
    n = events.count()
    t_parse = time.time() - t0

    win = window_aggregates(events).cache()
    feats = ip_features(events, win).join(ip_rule_hits(win), "ip", "left").fillna({"rule_flag": False})
    feats = feats.cache()
    feats.count()
    t_feat = time.time() - t0 - t_parse

    scored, _ = ml_detect(feats, k_range=[5], choose_k=False)
    scored.where(F.col("ml_flag")).count()
    total = time.time() - t0
    events.unpersist(); win.unpersist(); feats.unpersist()
    return {"scale": f"{scale}x", "events": n, "parse_s": round(t_parse, 2), "features_rules_s": round(t_feat, 2),
            "kmeans_s": round(total - t_parse - t_feat, 2), "total_s": round(total, 2),
            "events_per_s": round(n / total)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scales", default="1,5,10")
    args = ap.parse_args()
    spark = get_spark("auth-benchmark")
    run_once(spark, 1)  # warm-up: JVM, code generation
    rows = []
    for s in [int(x) for x in args.scales.split(",")]:
        r = run_once(spark, s)
        rows.append(r)
        print(r)
    df = pd.DataFrame(rows)
    df.to_csv(config.OUT / "benchmark.csv", index=False)

    fig, ax = plt.subplots(figsize=(7, 4))
    bottom = [0] * len(df)
    for i, (col, name) in enumerate([("parse_s", "Parse"), ("features_rules_s", "Features + rules"),
                                     ("kmeans_s", "KMeans + PCA")]):
        ax.bar(df["scale"], df[col], 0.55, bottom=bottom, color=config.COLORS[i], label=name,
               edgecolor="white", linewidth=2)
        bottom = [b + v for b, v in zip(bottom, df[col])]
    for x, (tot, n) in enumerate(zip(df["total_s"], df["events"])):
        ax.text(x, tot, f"{tot:.0f}s\n{n / 1e6:.2f}M events", ha="center", va="bottom", fontsize=8)
    ax.set_ylim(0, max(bottom) * 1.25)
    style(ax, f"Spark pipeline runtime vs. data volume ({spark.sparkContext.defaultParallelism} cores, local mode)",
          "Data volume", "Seconds")
    ax.legend(frameon=False, fontsize=8, loc="upper left")
    fig.savefig(config.FIG / "scalability.png", dpi=150, bbox_inches="tight")
    print(df.to_string(index=False))
    spark.stop()


if __name__ == "__main__":
    main()
