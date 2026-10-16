# End-to-end run with Docker Desktop. Usage: .\run_all.ps1   (add -Stream to also demo Kafka streaming)
param([switch]$Stream)
$ErrorActionPreference = "Stop"

function Job($script, $jobArgs = "") {
    Write-Host "`n=== $script ===" -ForegroundColor Cyan
    docker compose run --rm --service-ports spark sh -c "python src/$script $jobArgs"
    if ($LASTEXITCODE -ne 0) { throw "$script failed" }
}

docker compose up -d kafka elasticsearch kibana neo4j
docker compose build spark

Job "01_generate_data.py"
Job "04_batch_analytics.py"
Job "05_forecast.py"
Write-Host "Waiting for Neo4j (GDS plugin downloads on first start)..."
Start-Sleep -Seconds 30
Job "06_neo4j_graph.py"
Job "07_elastic_load.py"
Job "08_benchmark.py"

if ($Stream) {
    Write-Host "`nStarting streaming detector in a new window; producer replays the log into Kafka."
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "docker compose run --rm --service-ports spark python src/03_stream_detect.py"
    Start-Sleep -Seconds 60
    docker compose run --rm spark python src/02_kafka_producer.py --rate 2000
}

Write-Host "`nDone. Figures: output\figures   Kibana: http://localhost:5601   Neo4j: http://localhost:7474 (neo4j / bigdata123)"
