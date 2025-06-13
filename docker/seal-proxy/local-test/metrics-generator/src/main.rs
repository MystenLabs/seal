use anyhow::Result;
use tokio::time::{sleep, Duration};
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<()> {
    push_metrics().await?;
    Ok(())
}

fn generate_metrics() -> String {
    let timestamp = chrono::Utc::now().timestamp_millis();
    let mut metrics = Vec::new();
    
    // CPU usage metric
    let cpu_usage = rand::random::<f64>() * 100.0;
    metrics.push(format!("cpu_usage{{host=\"demo\"}} {} {}", cpu_usage, timestamp));
    
    // Memory usage metric
    let memory_usage = rand::random::<f64>() * 16.0;
    metrics.push(format!("memory_usage{{host=\"demo\"}} {} {}", memory_usage, timestamp));
    
    // Request count metric
    let request_count = rand::random::<u32>() % 1000 + 100;
    metrics.push(format!("http_requests_total{{host=\"demo\",status=\"200\"}} {} {}", request_count, timestamp));
    
    // Response time metric
    let response_time = rand::random::<f64>() * 2.0 + 0.1;
    metrics.push(format!("http_response_time_seconds{{host=\"demo\"}} {} {}", response_time, timestamp));
    
    metrics.join("\n")
}

async fn push_metrics() -> Result<()> {
    let client = reqwest::Client::new();
    let url = "http://seal-proxy:8000/publish/metrics";

    loop {
        let metrics = generate_metrics();
        match client.post(url).body(metrics).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Metrics pushed successfully");
                } else {
                    error!("Failed to push metrics: {}", response.status());
                }
            }
            Err(e) => {
                error!("Error pushing metrics: {}", e);
            }
        }
        sleep(Duration::from_secs(5)).await;
    }
}
