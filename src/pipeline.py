"""Spark building blocks shared by the batch, streaming and benchmark jobs."""
import math
import os

import pyspark
from pyspark.ml import Pipeline
from pyspark.ml.clustering import KMeans
from pyspark.ml.evaluation import ClusteringEvaluator
from pyspark.ml.feature import PCA, StandardScaler, VectorAssembler
from pyspark.ml.functions import vector_to_array
from pyspark.sql import SparkSession, Window
from pyspark.sql import functions as F

import config

IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
LINE_RE = r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+(.*)$"
FAILED_RE = rf"Failed password for (invalid user )?(\S*) from {IP} port \d+"
ACCEPTED_RE = rf"Accepted \w+ for (\S+) from {IP} port \d+"
INVALID_RE = rf"Invalid user (\S*) from {IP}"

ML_FEATURES = ["n_events", "n_failed", "n_success", "distinct_users", "distinct_hosts", "fail_ratio",
               "invalid_ratio", "active_hours", "mean_gap_s", "max_fails_5min",
               "max_fails_before_success", "attempts_per_user"]


def get_spark(app, kafka=False):
    builder = (SparkSession.builder.appName(app)
               .master(os.getenv("SPARK_MASTER", "local[*]"))
               .config("spark.driver.memory", os.getenv("SPARK_DRIVER_MEMORY", "4g"))
               .config("spark.sql.shuffle.partitions", os.getenv("SHUFFLE_PARTITIONS", "8"))
               .config("spark.sql.session.timeZone", "UTC")
               .config("spark.sql.legacy.timeParserPolicy", "CORRECTED"))
    if kafka:
        scala = "2.13" if pyspark.__version__.startswith("4") else "2.12"
        builder = builder.config("spark.jars.packages",
                                 f"org.apache.spark:spark-sql-kafka-0-10_{scala}:{pyspark.__version__}")
    if os.getenv("IVY_DIR"):
        builder = builder.config("spark.jars.ivy", os.getenv("IVY_DIR"))
    spark = builder.getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    return spark


def parse_lines(df, col="value"):
    """Raw sshd syslog lines -> one row per auth event (FAILED / SUCCESS / INVALID_USER)."""
    d = df.select(
        F.regexp_extract(col, LINE_RE, 1).alias("mon"),
        F.regexp_extract(col, LINE_RE, 2).alias("day"),
        F.regexp_extract(col, LINE_RE, 3).alias("hms"),
        F.regexp_extract(col, LINE_RE, 4).alias("host"),
        F.regexp_extract(col, LINE_RE, 5).alias("msg"),
    ).select(
        "host",
        F.to_timestamp(F.concat_ws(" ", F.lit(str(config.LOG_YEAR)), "mon", "day", "hms"),
                       "yyyy MMM d HH:mm:ss").alias("ts"),
        F.regexp_extract("msg", FAILED_RE, 1).alias("f_inv"),
        F.regexp_extract("msg", FAILED_RE, 2).alias("f_user"),
        F.regexp_extract("msg", FAILED_RE, 3).alias("f_ip"),
        F.regexp_extract("msg", ACCEPTED_RE, 1).alias("a_user"),
        F.regexp_extract("msg", ACCEPTED_RE, 2).alias("a_ip"),
        F.regexp_extract("msg", INVALID_RE, 1).alias("i_user"),
        F.regexp_extract("msg", INVALID_RE, 2).alias("i_ip"),
    )
    event = (F.when(F.col("f_ip") != "", "FAILED")
             .when(F.col("a_ip") != "", "SUCCESS")
             .when(F.col("i_ip") != "", "INVALID_USER"))
    d = d.withColumn("event", event).where(F.col("event").isNotNull() & F.col("ts").isNotNull())
    pick = lambda f, a, i: (F.when(F.col("event") == "FAILED", F.col(f))
                            .when(F.col("event") == "SUCCESS", F.col(a)).otherwise(F.col(i)))
    return d.select(
        "ts", F.to_date("ts").alias("date"), "host", "event",
        pick("f_user", "a_user", "i_user").alias("user"),
        pick("f_ip", "a_ip", "i_ip").alias("ip"),
        ((F.col("f_inv") != "") | (F.col("event") == "INVALID_USER")).alias("invalid_user"),
    )


def with_flags(events):
    return (events
            .withColumn("is_failed", (F.col("event") == "FAILED").cast("int"))
            .withColumn("is_success", (F.col("event") == "SUCCESS").cast("int"))
            .withColumn("is_probe", (F.col("event") == "INVALID_USER").cast("int"))
            .withColumn("is_invalid", F.col("invalid_user").cast("int")))


def window_aggregates(events, streaming=False):
    """Per IP per tumbling window counts. Streaming cannot use exact countDistinct."""
    distinct = F.approx_count_distinct if streaming else F.countDistinct
    return events.groupBy("ip", F.window("ts", config.RULE_WINDOW)).agg(
        F.sum("is_failed").alias("fails"),
        distinct(F.when(F.col("is_failed") == 1, F.col("user"))).alias("users_failed"),
        F.sum("is_probe").alias("invalid_probes"),
        F.sum("is_success").alias("successes"),
    )


def apply_rules(win):
    """Threshold rules on window aggregates. Priority picks one type per window."""
    win = (win
           .withColumn("r_brute", F.col("fails") >= config.BRUTE_FORCE_FAILS)
           .withColumn("r_spray", F.col("users_failed") >= config.SPRAY_DISTINCT_USERS)
           .withColumn("r_enum", F.col("invalid_probes") >= config.ENUM_INVALID_PROBES)
           .withColumn("r_comp", (F.col("successes") > 0) & (F.col("fails") >= config.COMPROMISE_FAILS)))
    return win.withColumn("rule_type",
                          F.when(F.col("r_comp"), "post_compromise")
                          .when(F.col("r_enum"), "user_enumeration")
                          .when(F.col("r_spray"), "password_spraying")
                          .when(F.col("r_brute"), "brute_force"))


def ip_rule_hits(win):
    rules = apply_rules(win)
    rank = F.when(F.col("rule_type") == "post_compromise", 4).when(F.col("rule_type") == "user_enumeration", 3) \
        .when(F.col("rule_type") == "password_spraying", 2).when(F.col("rule_type") == "brute_force", 1)
    return (rules.where(F.col("rule_type").isNotNull())
            .groupBy("ip")
            .agg(F.max(F.struct(rank.alias("r"), F.col("rule_type"))).alias("top"),
                 F.count("*").alias("rule_windows"))
            .select("ip", F.lit(True).alias("rule_flag"), F.col("top.rule_type").alias("rule_type"), "rule_windows"))


def ip_features(events, win):
    """Behavioural features per IP over the whole period (window functions + aggregates)."""
    w = Window.partitionBy("ip").orderBy("ts")
    ev = (events
          .withColumn("gap_s", F.col("ts").cast("long") - F.lag("ts").over(w).cast("long"))
          # group id = successes seen before this row, so each success closes its group of failures
          .withColumn("grp", F.coalesce(F.sum("is_success").over(w.rowsBetween(Window.unboundedPreceding, -1)),
                                        F.lit(0))))
    base = ev.groupBy("ip").agg(
        F.count("*").alias("n_events"),
        F.sum("is_failed").alias("n_failed"),
        F.sum("is_success").alias("n_success"),
        F.sum("is_invalid").alias("n_invalid"),
        F.countDistinct("user").alias("distinct_users"),
        F.countDistinct("host").alias("distinct_hosts"),
        F.countDistinct(F.date_trunc("hour", "ts")).alias("active_hours"),
        F.avg("gap_s").alias("mean_gap_s"),
        F.min("ts").alias("first_seen"),
        F.max("ts").alias("last_seen"),
    )
    groups = ev.groupBy("ip", "grp").agg(F.sum("is_failed").alias("fails"), F.max("is_success").alias("ok"))
    compromise = groups.groupBy("ip").agg(
        F.max(F.when(F.col("ok") == 1, F.col("fails")).otherwise(0)).alias("max_fails_before_success"))
    burst = win.groupBy("ip").agg(F.max("fails").alias("max_fails_5min"))

    feats = base.join(compromise, "ip").join(burst, "ip")
    return (feats
            .withColumn("fail_ratio", 1 - F.col("n_success") / F.col("n_events"))
            .withColumn("invalid_ratio", F.col("n_invalid") / F.col("n_events"))
            .withColumn("attempts_per_user", (F.col("n_events") - F.col("n_success")) / F.col("distinct_users"))
            .withColumn("mean_gap_s", F.coalesce("mean_gap_s", F.lit(86400.0)))
            .withColumn("success_after_fails", F.col("max_fails_before_success") >= config.SUCCESS_AFTER_FAILS))


def profile_type():
    """Name the attack behind a flagged IP from its behavioural profile."""
    c = F.col
    return (F.when(c("success_after_fails"), "post_compromise")
            .when((c("invalid_ratio") > 0.6) & (c("n_failed") < 0.5 * c("n_events")), "user_enumeration")
            .when((c("distinct_users") >= 10) & (c("attempts_per_user") <= 3) & (c("max_fails_5min") <= 5),
                  "password_spraying")
            .when((c("distinct_users") >= 10) & (c("attempts_per_user") <= 3), "credential_stuffing")
            .when(c("max_fails_5min") >= config.BRUTE_FORCE_FAILS, "brute_force")
            .when(c("fail_ratio") < 0.5, "anomalous_activity")  # outlier that mostly succeeds, e.g. automation
            .otherwise("low_and_slow"))


def ml_detect(feats, k_range=range(3, 9), seed=42, choose_k=True):
    """StandardScaler -> KMeans (k by silhouette) -> PCA(2). Flags malicious clusters and outliers."""
    df = feats
    for c in ML_FEATURES:
        df = df.withColumn(f"log_{c}", F.log1p(F.col(c).cast("double")))
    prep = Pipeline(stages=[
        VectorAssembler(inputCols=[f"log_{c}" for c in ML_FEATURES], outputCol="raw_vec"),
        StandardScaler(inputCol="raw_vec", outputCol="features", withMean=True, withStd=True),
    ]).fit(df)
    X = prep.transform(df).cache()

    evaluator = ClusteringEvaluator(featuresCol="features")
    scores, best = [], None
    for k in (k_range if choose_k else [k_range[0]]):
        model = KMeans(k=k, seed=seed, featuresCol="features", predictionCol="cluster").fit(X)
        score = evaluator.evaluate(model.transform(X).withColumnRenamed("cluster", "prediction"))
        scores.append((k, score))
        if best is None or score > best[1]:
            best = (k, score, model)
    k, silhouette, model = best

    centers = [c.tolist() for c in model.clusterCenters()]

    @F.udf("double")
    def dist_to_center(vec, cluster):
        return float(math.sqrt(sum((a - b) ** 2 for a, b in zip(vec.toArray(), centers[cluster]))))

    pred = model.transform(X).withColumn("dist", dist_to_center("features", "cluster"))
    pca_model = PCA(k=2, inputCol="features", outputCol="pca").fit(pred)
    out = pca_model.transform(pred).withColumn("pca_arr", vector_to_array("pca"))

    # Cluster profiling: a cluster whose members mostly fail to authenticate is malicious
    profile = out.groupBy("cluster").agg(F.count("*").alias("size"), F.avg("fail_ratio").alias("avg_fail_ratio"),
                                         F.avg("distinct_users").alias("avg_distinct_users"),
                                         F.avg("n_events").alias("avg_events"))
    bad = [r["cluster"] for r in profile.where(F.col("avg_fail_ratio") > 0.5).collect()]
    stats = out.agg(F.avg("dist").alias("m"), F.stddev("dist").alias("s")).first()
    cutoff = stats["m"] + 3 * (stats["s"] or 0)

    out = (out
           .withColumn("malicious_cluster", F.col("cluster").isin(bad) if bad else F.lit(False))
           .withColumn("outlier", F.col("dist") > cutoff)
           .withColumn("ml_flag", F.col("malicious_cluster") | F.col("outlier"))
           .withColumn("pca_x", F.col("pca_arr")[0])
           .withColumn("pca_y", F.col("pca_arr")[1])
           .drop("raw_vec", "features", "pca", "pca_arr", *[f"log_{c}" for c in ML_FEATURES]))
    info = {"k": k, "silhouette": silhouette, "k_scores": scores, "profile": profile.toPandas(),
            "explained_variance": pca_model.explainedVariance.toArray().tolist(), "outlier_cutoff": cutoff}
    return out, info


def mitre_columns(type_col):
    pairs = []
    for name, (tid, tname) in config.MITRE.items():
        pairs += [F.lit(name), F.lit(f"{tid}|{tname}")]
    m = F.create_map(*pairs)[F.col(type_col)]
    return F.split(m, r"\|")[0], F.split(m, r"\|")[1]
