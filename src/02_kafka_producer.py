"""Replay data/raw/auth.log into Kafka, one message per sshd line, keyed by host."""
import argparse
import time

from kafka import KafkaProducer
from kafka.admin import KafkaAdminClient, NewTopic
from kafka.errors import TopicAlreadyExistsError

import config


def ensure_topic(partitions):
    admin = KafkaAdminClient(bootstrap_servers=config.KAFKA_BOOTSTRAP)
    try:
        admin.create_topics([NewTopic(config.KAFKA_TOPIC, num_partitions=partitions, replication_factor=1)])
        print(f"Created topic {config.KAFKA_TOPIC} with {partitions} partitions")
    except TopicAlreadyExistsError:
        pass
    finally:
        admin.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rate", type=int, default=2000, help="lines per second (0 = as fast as possible)")
    ap.add_argument("--limit", type=int, default=0, help="stop after N lines (0 = all)")
    ap.add_argument("--partitions", type=int, default=3)
    args = ap.parse_args()

    ensure_topic(args.partitions)
    producer = KafkaProducer(bootstrap_servers=config.KAFKA_BOOTSTRAP, linger_ms=20, acks=1,
                             key_serializer=str.encode, value_serializer=str.encode)
    sent, started = 0, time.time()
    with open(config.RAW_LOG, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            parts = line.split()
            producer.send(config.KAFKA_TOPIC, key=parts[3] if len(parts) > 3 else "", value=line)
            sent += 1
            if args.rate and sent % args.rate == 0:
                elapsed = time.time() - started
                time.sleep(max(0.0, sent / args.rate - elapsed))
                print(f"sent {sent:,} lines ({sent / max(elapsed, 1e-9):,.0f}/s)")
            if args.limit and sent >= args.limit:
                break
    producer.flush()
    print(f"Done: {sent:,} lines to topic {config.KAFKA_TOPIC} in {time.time() - started:.1f}s")


if __name__ == "__main__":
    main()
