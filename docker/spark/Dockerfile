# PySpark runner: Python 3.11 + Java 17, so nothing needs installing on the host
FROM python:3.11-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends openjdk-17-jre-headless procps \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

ENV PYTHONUNBUFFERED=1 \
    KAFKA_BOOTSTRAP=kafka:29092 \
    ES_URL=http://elasticsearch:9200 \
    KIBANA_URL=http://kibana:5601 \
    NEO4J_URI=bolt://neo4j:7687 \
    IVY_DIR=/app/.ivy2
