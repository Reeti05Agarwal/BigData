"""Spark Structured Streaming: Kafka -> parse -> 5-minute windowed rules -> Elasticsearch + Parquet.

Three sinks run at once:
  1. raw parsed events  -> Parquet (data lake) and Elasticsearch index auth-stream-events
  2. window alerts      -> Elasticsearch index auth-stream-alerts (live Kibana dashboard)
  3. window alerts      -> console, so the demo shows detections as they happen
"""
import argparse

from elasticsearch import Elasticsearch, helpers
from pyspark.sql import functions as F

import config
from pipeline import apply_rules, get_spark, mitre_columns, parse_lines, window_aggregates, with_flags

EVENTS_INDEX = "auth-stream-events"
ALERTS_INDEX = "auth-stream-alerts"


def es_writer(index, id_fn):
    def write(batch_df, batch_id):
        rows = batch_df.collect()
        if not rows:
            return
        es = Elasticsearch(config.ES_URL)
        actions = []
        for r in rows:
            doc = r.asDict()
            for k, v in doc.items():
                if hasattr(v, "isoformat"):
                    doc[k] = v.isoformat()
            action = {"_index": index, "_source": doc}
            doc_id = id_fn(doc)
            if doc_id:
                action["_id"] = doc_id
            actions.append(action)
        helpers.bulk(es, actions)
        print(f"[batch {batch_id}] {len(actions)} docs -> {index}")
    return write


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-es", action="store_true", help="skip Elasticsearch sinks (console + Parquet only)")
    ap.add_argument("--trigger", default="10 seconds")
    args = ap.parse_args()

    spark = get_spark("auth-stream-detect", kafka=True)
    lines = (spark.readStream.format("kafka")
             .option("kafka.bootstrap.servers", config.KAFKA_BOOTSTRAP)
             .option("subscribe", config.KAFKA_TOPIC)
             .option("startingOffsets", "earliest")
             .option("maxOffsetsPerTrigger", 50000)
             .load()
             .select(F.col("value").cast("string").alias("value")))

    events = with_flags(parse_lines(lines))

    # Sink 1: data lake + raw events for Kibana
    (events.writeStream.format("parquet")
     .option("path", str(config.STREAM_PARQUET))
     .option("checkpointLocation", str(config.CHECKPOINTS / "stream_parquet"))
     .partitionBy("date").trigger(processingTime=args.trigger).start())
    if not args.no_es:
        (events.select("ts", "host", "event", "user", "ip", "invalid_user")
         .withColumnRenamed("ts", "@timestamp")
         .writeStream.foreachBatch(es_writer(EVENTS_INDEX, lambda d: None))
         .option("checkpointLocation", str(config.CHECKPOINTS / "stream_es_events"))
         .trigger(processingTime=args.trigger).start())

    # Sink 2/3: windowed threshold rules with a watermark for late events
    win = window_aggregates(events.withWatermark("ts", "10 minutes"), streaming=True)
    alerts = apply_rules(win).where(F.col("rule_type").isNotNull())
    tid, tname = mitre_columns("rule_type")
    alerts = alerts.select(
        F.col("window.start").alias("@timestamp"), F.col("window.end").alias("window_end"), "ip",
        "fails", "users_failed", "invalid_probes", "successes", "rule_type",
        tid.alias("technique_id"), tname.alias("technique_name"))

    if not args.no_es:
        (alerts.writeStream.outputMode("update")
         .foreachBatch(es_writer(ALERTS_INDEX, lambda d: f"{d['ip']}_{d['@timestamp']}"))
         .option("checkpointLocation", str(config.CHECKPOINTS / "stream_es_alerts"))
         .trigger(processingTime=args.trigger).start())
    (alerts.writeStream.outputMode("update").format("console")
     .option("truncate", False).option("numRows", 20)
     .trigger(processingTime=args.trigger).start())

    print(f"Streaming from Kafka topic '{config.KAFKA_TOPIC}'. Spark UI: http://localhost:4040  (Ctrl+C to stop)")
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()
