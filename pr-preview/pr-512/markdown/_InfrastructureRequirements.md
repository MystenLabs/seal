The server is a lightweight, stateless service designed for easy horizontal scaling. Because it doesn't require persistent storage, you can run multiple instances behind a load balancer to increase availability and resilience. Each instance must have access to a trusted [Sui full node](https://docs.sui.io/guides/operator/sui-full-node) — ideally one that's geographically close to reduce latency during policy checks and key operations.

To operate the server securely, it is recommended to place it behind an API gateway or reverse proxy. This allows you to:

- Expose the service over HTTPS and terminate SSL/TLS at the edge
- Enforce rate limiting and prevent abuse
- Authenticate requests using API keys or access tokens
- Optionally integrate usage tracking for commercial or billable offerings, such as logging access frequency per client or package

For observability, the server exposes Prometheus-compatible metrics on port `9184`. You can access raw metrics by running `curl http://0.0.0.0:9184`. These metrics can also be visualized using tools like Grafana. The key server also includes a basic health check endpoint on port `2024`: `curl http://0.0.0.0:2024/health`.

### CORS configuration

Configure Cross-Origin Resource Sharing (CORS) on your server to allow applications to make requests directly from the browser. Use the following recommended headers:
```shell
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Request-Id, Client-Sdk-Type, Client-Sdk-Version
Access-Control-Expose-Headers: x-keyserver-version
```

If your server requires an API key, make sure to include the corresponding HTTP header name in `Access-Control-Allow-Headers` as well.