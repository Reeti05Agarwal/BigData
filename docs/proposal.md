I've rewritten your proposal to match the CA-3 rubric. **One thing to check first:** the notice says the deadline was **11 Oct, 8:00 AM**, and today is 16 Oct. If you don't have an extension, ask about late submission before doing anything else.

## What I changed and why

| Rubric gap | Change |
|---|---|
| The rubric names **Kafka**, and you had no streaming | Added Kafka plus Spark Structured Streaming for live detection. This adds the most Big Data marks. |
| The rubric names **Kibana/Grafana/D3**, and Matplotlib doesn't count | Spark writes results to Elasticsearch, and a **Kibana** dashboard shows them. Matplotlib is kept only for figures in the report. |
| Too much to finish in the time you have | Dropped the MapReduce comparison and ARIMA. Neither is in the rubric. |
| Random Forest trained on rule-made labels just copies the rules | Inject **synthetic attacks with known labels** into real logs. That gives true ground truth and fixes your stated limitation. |
| Rubric not addressed directly | Added a rubric mapping table. Examiners grade faster against one. |

---

## Revised proposal (paste and edit)

**Detecting Coordinated Multi-Stage Attacks in Authentication Logs Using Kafka, Spark, MLlib, Neo4j and Kibana**

### Abstract
This project builds a distributed batch and streaming pipeline that detects attacks in large SSH authentication logs. Kafka streams the log events. Spark Structured Streaming parses them and builds per-IP features over sliding time windows. Fixed-threshold rules are compared with Spark MLlib models (PCA, then KMeans and Random Forest). The goal is to show which stealthy attacks the rules miss, such as password spraying and low-and-slow brute force. Each detection is mapped to a MITRE ATT&CK technique. Results go to Elasticsearch for a live Kibana SOC dashboard and to Neo4j, where Louvain community detection finds coordinated botnet campaigns. Scalability is measured at 1x, 10x, 50x and 100x data volume.

### Problem Statement
Authentication logs grow to millions of events a day. Static rules fire false alarms, miss attackers who stay just under the threshold, and look at each IP alone, so they can't link the IPs in a distributed campaign. A SOC needs a pipeline that scales with the data, works in near real time, tells attack types apart and shows how attackers are connected.

### Objectives
1. Ingest auth logs as a stream with Kafka and process them with Spark Structured Streaming. Store the parsed logs as Parquet for batch analysis.
2. Detect brute force, password spraying, credential stuffing, user enumeration and post-compromise logins.
3. Compare rule-based and ML detection using precision, recall and F1.
4. Map every detection to a MITRE ATT&CK technique (T1110.001, T1110.003, T1110.004, T1087, T1078).
5. Use Neo4j to find coordinated campaigns and the most central attacker IPs.
6. Show live insights in a Kibana dashboard and measure scalability.

### Dataset
- **Loghub OpenSSH logs** (real SSH auth logs, about 655K lines), replicated up to 100x for the scale tests.
- **Ground truth:** a Python generator injects labelled synthetic attacks of each type into the real logs at known times and IPs. This gives true labels for precision, recall and F1.

### Tech Stack

| Tool | Stage | Why |
|---|---|---|
| Apache Kafka | Ingestion | Streams log events in real time and decouples producers from consumers |
| Spark Structured Streaming | Parsing, windowed features | Distributed in-memory processing with event-time windows and watermarks |
| Parquet | Storage | Compressed columnar format, fast for batch ML |
| Spark MLlib | PCA, KMeans, Random Forest | Machine learning that runs on the cluster |
| Neo4j + Cypher (GDS) | Attack graph | Relationship queries, Louvain communities, PageRank centrality (CO5) |
| Elasticsearch + Kibana | SOC dashboard | Live attack map, timelines, risk-score table (rubric visualization tool) |
| Holt-Winters (statsmodels) | Hourly failed logins | Forecast baseline and spike detection |

### Pipeline
`Log replay producer → Kafka topic → Spark Structured Streaming (regex parse → 5-min/1-hr windowed features) → [Rules | MLlib models] → ATT&CK tagging → Elasticsearch/Kibana + Neo4j + Parquet`

### Features (per IP, per window)
Failed and successful login counts, number of distinct usernames tried, fail-to-success ratio, share of invalid users, mean time between attempts, number of distinct hosts targeted, and whether a success came right after a run of failures. That last one signals a post-compromise login.

### Methodology
1. **Ingest:** a Python producer replays the logs into Kafka.
2. **Parse and clean:** Spark regex extraction, written to Parquet.
3. **Feature engineering:** window functions over sliding windows.
4. **Baseline:** threshold rules (for example, more than 10 failures in 5 minutes).
5. **ML detection:** PCA, then KMeans (unsupervised) and Random Forest (supervised, trained on the injected labels).
6. **Forecasting:** Holt-Winters on hourly failed logins, flagging values outside the forecast band.
7. **Graph:** load `(:IP)-[:ATTEMPTED]->(:User)` and `(:IP)-[:TARGETED]->(:Host)` into Neo4j, then run Louvain and PageRank.
8. **Evaluate:** precision, recall and F1 for rules vs. RF vs. KMeans, plus runtime and throughput at 1x, 10x, 50x and 100x.
9. **Visualize:** Kibana dashboard, Neo4j Browser graph, PCA scatter plot and confusion matrices.

### Visualizations and Insights
- **Kibana:** live failed-login timeline, top attacker IPs, attacks by ATT&CK technique, geo map, per-IP risk-score table
- **Neo4j:** botnet clusters coloured by Louvain community
- **Report figures:** PCA 2D plot (normal vs. attacker), rules vs. ML F1 bar chart, scalability line chart, forecast with flagged anomalies

### Innovation and Real-World Relevance
- Combines streaming detection, ML and graph analysis. Most student projects stop at one of these.
- Synthetic attack injection gives true ground truth, which public auth datasets don't have.
- Output is ATT&CK-tagged, so a SOC team can use it directly.
- Graph analysis shows campaigns that per-IP rules can't see.

### Rubric Mapping

| Criterion | Where it's covered |
|---|---|
| Problem Identification | Rules don't scale and miss distributed, low-and-slow attacks across millions of events |
| Tool/Framework Usage | Kafka, Spark Structured Streaming, MLlib, Neo4j, Kibana |
| Data Processing & Analysis | Streaming ETL, windowed features, PCA, KMeans/RF, Louvain, scale test |
| Visualization & Insights | Kibana dashboard, Neo4j graph, PCA and F1 charts |
| Innovation & Relevance | Synthetic ground truth, ATT&CK mapping, campaign detection |
| Report | Structured sections, own wording, cited dataset and tools |

### Limitations
- The attack labels come from injected synthetic attacks, not real incidents. Real-world precision may be lower.
- The scale test runs in single-node Spark local mode, so the numbers show relative scaling only, not cluster performance.

---

## Shortest path to finishing
1. Run everything with Docker Compose: Kafka, Elasticsearch, Kibana and Neo4j. Run PySpark locally.
2. Write one notebook each for ingest and features, ML, and graph.
3. Take screenshots of Kibana and Neo4j for the report. Those screenshots carry the visualization marks.
4. Write the report in your own words, since the rubric checks for plagiarism.
5. Name the folder `PRN_CSE_Batch_FirstName_LastName`.

I can write the code next if you want. That would be the Docker Compose file, the Kafka producer, the Spark streaming job and the MLlib notebook.