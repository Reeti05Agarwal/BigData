# Detecting Coordinated Multi-Stage SSH Attacks with Kafka, Spark, MLlib, Neo4j and Kibana

Big Data Analytics CA-3 case study. Proposal and rubric mapping: [docs/proposal.md](docs/proposal.md).

## Architecture

```
auth.log ──► Kafka topic "auth-logs" ──► Spark Structured Streaming ──► 5-min window rules ──► Elasticsearch ──► Kibana (live)
   │                                         └──► Parquet data lake (partitioned by date)
   └──────────► Spark batch ──► Parquet ──► per-IP features (window functions)
                                   ├──► threshold rules ─┐
                                   ├──► MLlib: StandardScaler ► KMeans (k by silhouette) ► PCA
                                   │                      └► MITRE ATT&CK tagging ► risk score
                                   ├──► hourly series ──► Holt-Winters forecast + anomaly flags
                                   └──► IP–User / IP–Host edges ──► Neo4j ──► Louvain + PageRank ──► campaigns
```

| Stage | Tool | File |
|---|---|---|
| Labelled data (benign + 6 attack types) | Python | [src/01_generate_data.py](src/01_generate_data.py) |
| Streaming ingestion | Kafka | [src/02_kafka_producer.py](src/02_kafka_producer.py) |
| Real-time detection | Spark Structured Streaming | [src/03_stream_detect.py](src/03_stream_detect.py) |
| Parsing, features, rules, ML, evaluation | Spark SQL + MLlib | [src/04_batch_analytics.py](src/04_batch_analytics.py), [src/pipeline.py](src/pipeline.py) |
| Time-series anomaly detection | statsmodels Holt-Winters | [src/05_forecast.py](src/05_forecast.py) |
| Attack graph, campaigns | Neo4j + GDS | [src/06_neo4j_graph.py](src/06_neo4j_graph.py) |
| SOC dashboard | Elasticsearch + Kibana | [src/07_elastic_load.py](src/07_elastic_load.py) |
| Scalability (1x / 10x / 50x / 100x) | Spark | [src/08_benchmark.py](src/08_benchmark.py) |

## Attack types and ground truth

The generator writes realistic sshd syslog lines and a label file for every synthetic IP.

| Attack | Behaviour | MITRE | Caught by 5-min rules? |
|---|---|---|---|
| Brute force | 300–800 guesses at 1–3 s on root/admin | T1110.001 | Yes |
| Low-and-slow | one guess every 3–9 min for 1.5–2.5 days | T1110.001 | No, stays under threshold |
| Password spraying | 20-bot botnet, one password per round across 40 real users | T1110.003 | No, ~1 attempt per bot per window |
| Credential stuffing | 8 IPs, shared leaked list of 400 usernames | T1110.004 | Partly (as brute force) |
| User enumeration | "Invalid user" probes, 3 fast and 3 slow scanners | T1087 | Fast ones only |
| Post-compromise | slow guessing, then success and logins to db01/web02 | T1078 | No |

Enumeration, spraying and post-compromise form one campaign (**APT-SSH-1**): the scanners find valid
usernames, the botnet sprays them, and two IPs from the botnet subnets get in and move laterally.
Benign traffic includes edge cases that trip rules: users who forgot a password (12 fails then success) and
a backup account with 96 logins a day.

To add real background traffic, download `SSH.log` from [Loghub](https://github.com/logpai/loghub) and run
`python src/01_generate_data.py --real data/raw/SSH.log`. Real IPs are processed and graphed but left out of
precision/recall because they have no labels.

## Run it

You need Docker Desktop. Everything else, including Spark and Java, runs in containers.

```powershell
.\run_all.ps1            # batch pipeline, graph, Kibana load, benchmark
.\run_all.ps1 -Stream    # plus the live Kafka -> Spark Streaming demo
```

### On Arch Linux

```bash
sudo pacman -S --needed docker docker-compose docker-buildx
sudo systemctl enable --now docker
sudo usermod -aG docker $USER          # then log out and back in (or run: newgrp docker)
sudo sysctl -w vm.max_map_count=262144 # Elasticsearch needs this on Linux
bash run_all.sh                        # or: bash run_all.sh --stream
```

To keep the `vm.max_map_count` setting across reboots:
`echo vm.max_map_count=262144 | sudo tee /etc/sysctl.d/99-elasticsearch.conf`.
Containers write as root, so `run_all.sh` hands `output/` and `data/` back to your user at the end.

Or step by step (the same commands work on Windows and Linux):

```powershell
docker compose up -d kafka elasticsearch kibana neo4j
docker compose run --rm spark python src/01_generate_data.py --users 300 --days 14
docker compose run --rm --service-ports spark python src/04_batch_analytics.py
docker compose run --rm spark python src/05_forecast.py
docker compose run --rm spark python src/06_neo4j_graph.py
docker compose run --rm spark python src/07_elastic_load.py
docker compose run --rm spark python src/08_benchmark.py
# streaming: start the detector, then replay the log into Kafka from a second terminal
docker compose run --rm --service-ports spark python src/03_stream_detect.py
docker compose run --rm spark python src/02_kafka_producer.py --rate 2000
```

For more volume, raise `--users` and `--days` (for example `--users 5000 --days 30` gives about 300K lines),
or merge the real Loghub log.

## Outputs

`output/` holds the CSVs and `output/figures/` the report charts:

| File | Shows |
|---|---|
| `metrics.csv`, `figures/metrics_comparison.png` | Precision, recall, F1: rules vs. KMeans vs. combined |
| `per_type_detection.csv`, `figures/detection_by_attack_type.png` | Which attack types rules miss |
| `figures/pca_scatter.png` | 2D PCA of per-IP behaviour, coloured by true type |
| `figures/kmeans_silhouette.png`, `cluster_profile.csv` | Choice of k and what each cluster looks like |
| `detections.csv`, `figures/top_risk_ips.png` | SOC triage list with MITRE technique and risk score |
| `hourly_forecast.csv`, `figures/forecast_anomalies.png` | Holt-Winters baseline and anomalous hours |
| `campaigns.csv`, `central_ips.csv`, `campaign_recovery.csv` | Louvain campaigns, PageRank, recovery of the true campaigns |
| `linked_campaigns.csv` | Attacker communities that share target accounts (multi-stage links, e.g. scanners → botnet) |
| `metrics_with_graph.csv`, `figures/detection_with_graph.png` | Graph-assisted detection: rules vs. KMeans vs. KMeans + Neo4j |
| `benchmark.csv`, `figures/scalability.png` | Runtime at 1x, 10x, 50x, 100x |

The Spark UI at http://localhost:4040 shows jobs, stages and the DAG while a job runs. Take a screenshot for the report.

## Kibana dashboard (http://localhost:5601)

`07_elastic_load.py` creates the data views. Set the time picker to **1 Sep 2026 – 1 Oct 2026**, then build these
panels with Lens (Dashboards → Create → Lens):

1. **Failed logins over time**: `auth-events`, date histogram on `@timestamp`, filter `event : "FAILED"`, break down by `attack_type`
2. **Attacks by MITRE technique**: `auth-ip-risk`, filter `ml_flag : true or rule_flag : true`, donut on `technique_name`
3. **Top attacker IPs**: `auth-ip-risk`, table of `ip`, `risk_score`, `predicted_type`, `technique_id`, `community`, sorted by risk
4. **Rules vs. ML**: `auth-ip-risk`, bar of count split by `rule_flag` and `ml_flag`
5. **Hourly anomalies**: `auth-hourly`, line of `failed` and `expected`, with `anomaly : true` as a filter
6. **Live alerts** (while streaming): `auth-stream-alerts`, table by `@timestamp`, `ip`, `rule_type`, `technique_id`

## Neo4j queries (http://localhost:7474, neo4j / bigdata123)

```cypher
// The APT campaign: scanners, botnet and compromised accounts sharing users
MATCH (i:IP)-[r:ATTEMPTED]->(u:User)
WHERE i.predicted_type IN ['user_enumeration','password_spraying','post_compromise']
RETURN i, r, u LIMIT 300

// Communities with several attacker IPs
MATCH (i:IP) WHERE i.ml_flag OR i.rule_flag
RETURN i.community AS community, count(*) AS ips, collect(DISTINCT i.predicted_type) AS stages
ORDER BY ips DESC

// Lateral movement: one IP logging in successfully to several hosts
MATCH (i:IP)-[t:TARGETED]->(h:Host) WHERE t.success > 0 AND i.ml_flag
WITH i, collect(h.name) AS hosts WHERE size(hosts) > 1
RETURN i.ip, hosts, i.risk_score
```

In Neo4j Browser, colour IP nodes by `community` to show the botnet clusters.

## Limitations

- Labels come from injected synthetic attacks, so real-world precision may be lower.
- Spark runs in local mode on one machine; the benchmark shows relative scaling, not cluster performance.
- The risk score is a weighted heuristic for triage ordering, not a calibrated probability.
- Random Forest (supervised) is left as future work; KMeans needs no labels, which suits real SOC data.
