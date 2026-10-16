"""Shared paths, service endpoints, rule thresholds and the MITRE ATT&CK map."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RAW_LOG = DATA / "raw" / "auth.log"
LABELS_CSV = DATA / "labels" / "ip_labels.csv"
EVENTS_PARQUET = DATA / "parquet" / "events"
STREAM_PARQUET = DATA / "parquet" / "stream_events"
CHECKPOINTS = DATA / "checkpoints"
OUT = ROOT / "output"
FIG = OUT / "figures"

# sshd syslog lines carry no year; the generator writes every line inside this year
LOG_YEAR = 2026
START_DATE = "2026-09-01"

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "auth-logs")
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "bigdata123")

# Classic SOC threshold rules, evaluated per IP in tumbling 5-minute windows
RULE_WINDOW = "5 minutes"
BRUTE_FORCE_FAILS = 10       # failed passwords in one window
SPRAY_DISTINCT_USERS = 10    # distinct usernames failed in one window
ENUM_INVALID_PROBES = 10     # "Invalid user" probes in one window
COMPROMISE_FAILS = 10        # failures followed by a success in one window

# Behavioural profile: a success preceded by at least this many failures
SUCCESS_AFTER_FAILS = 5

MITRE = {
    "brute_force": ("T1110.001", "Brute Force: Password Guessing"),
    "low_and_slow": ("T1110.001", "Brute Force: Password Guessing"),
    "password_spraying": ("T1110.003", "Brute Force: Password Spraying"),
    "credential_stuffing": ("T1110.004", "Brute Force: Credential Stuffing"),
    "user_enumeration": ("T1087", "Account Discovery"),
    "post_compromise": ("T1078", "Valid Accounts"),
}

# Categorical palette for report figures (fixed order, colour-blind checked)
COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
MUTED = "#898781"
INK = "#0b0b0b"
GRID = "#e1e0d9"
