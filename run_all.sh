#!/usr/bin/env bash
# End-to-end run on Linux. Usage: ./run_all.sh   (add --stream to also demo Kafka streaming)
set -euo pipefail
cd "$(dirname "$0")"

job() {
    echo -e "\n=== $1 ==="
    docker compose run --rm --service-ports spark python "src/$@"
}

docker compose up -d kafka elasticsearch kibana neo4j
docker compose build spark

job 01_generate_data.py
job 04_batch_analytics.py
job 05_forecast.py
echo "Waiting for Neo4j (GDS plugin downloads on first start)..."
sleep 30
job 06_neo4j_graph.py
job 07_elastic_load.py
job 08_benchmark.py

if [[ "${1:-}" == "--stream" ]]; then
    echo -e "\nStarting streaming detector in the background (log: output/stream.log)"
    docker compose run --rm --service-ports -d --name auth-stream spark \
        sh -c "python src/03_stream_detect.py > output/stream.log 2>&1"
    sleep 60
    docker compose run --rm spark python src/02_kafka_producer.py --rate 2000
    echo "Detector still running: tail -f output/stream.log   stop: docker stop auth-stream"
fi

# Containers run as root; hand the generated files back to you
docker compose run --rm spark chown -R "$(id -u):$(id -g)" /app/output /app/data

echo -e "\nDone. Figures: output/figures   Kibana: http://localhost:5601   Neo4j: http://localhost:7474 (neo4j / bigdata123)"
