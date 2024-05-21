# DDoS Protection Server

This is a Java-based server application that provides DDoS (Distributed Denial of Service) protection for your main servers. It acts as a proxy server, redirecting incoming traffic to the appropriate main server while implementing various DDoS mitigation techniques to prevent malicious attacks.

## Features

- **Connection Management**: Establish and manage connections between main server IP addresses and available ports on the DDoS protection server.
- **DDoS Protection Systems**:
  - **Rate Limiting**: Limits the number of requests allowed from a client IP address within a specific time period.
  - **IP Blacklisting**: Maintains a blacklist of IP addresses that have exceeded the DDoS attempt threshold and blocks requests from those addresses.
  - **CloudFlare Integration** (Planned): Integrates with CloudFlare's DDoS protection service for advanced DDoS mitigation capabilities.
- **IP Whitelisting**: Allows specifying a list of whitelisted IP addresses that bypass DDoS protection checks.
- **Captcha Challenge**: Implements a captcha challenge mechanism for clients that exceed the configured request rate limit.
- **HTTP Header Analysis**: Analyzes HTTP headers to detect potential DDoS attacks based on configured header patterns or anomalies.
- **Logging and Monitoring**:
  - Logs DDoS attempts and events to a file with configurable log levels.
  - Sends log messages to a Discord webhook for real-time monitoring.
- **Performance Tuning**: Configurable options for server performance, such as maximum concurrent connections and request queue size.
- **Highly Configurable**: The server is highly configurable through a `config.json` file, allowing you to adjust various settings like available ports, rate limits, blacklisting thresholds, and more.

## API

The server exposes a RESTful API for managing connections, configuring DDoS protection settings, and monitoring the server's status. Here are the available API endpoints:

- `POST /api` with a JSON payload containing the following commands:
  - `setconnection`: Establishes a connection between a main server IP address and an available port on the DDoS protection server.
  - `listports`: Lists the available and used ports on the server.
  - `connections`: Shows the current connections between main server IPs and DDoS protection server ports.
  - `deleteconnection`: Removes the connection between a main server IP address and the DDoS protection server.
  - `addiscordhook`: Adds a Discord webhook URL for logging DDoS attempts and events.
  - `addport`: Adds a new port to the list of available ports.
  - `setddossystem`: Sets the DDoS protection system to use (rateLimit, ipBlacklist, cloudFlare).

## CloudFlare Integration

The server supports integrating with CloudFlare's DDoS protection service. To enable this feature, you need to provide your CloudFlare API key and email address in the `config.json` file:



```json
{
  "cloudFlareApiKey": "your_api_key",
  "cloudFlareEmail": "your_email@example.com"
}
```
Once configured, the server will leverage CloudFlare's advanced DDoS mitigation capabilities to protect your main servers from various types of DDoS attacks.

## CloudFlare DDoS Protection

The CloudFlare DDoS protection system in this server utilizes the following techniques:

- **Web Application Firewall (WAF)**: CloudFlare's WAF inspects incoming traffic and blocks requests that exhibit malicious patterns or originate from known malicious IP addresses.
- **Rate Limiting**: CloudFlare's rate limiting mechanism restricts the number of requests a client can make within a specified time window, preventing excessive traffic from overwhelming your servers.
- **Load Balancing**: CloudFlare's global Anycast network distributes incoming traffic across multiple data centers, ensuring high availability and resilience against localized DDoS attacks.
- **DDoS Attack Mitigation**: CloudFlare's advanced DDoS mitigation technologies can detect and mitigate various types of DDoS attacks, including volumetric, protocol, and application-layer attacks.

By integrating with CloudFlare, this server can leverage these powerful DDoS protection capabilities to ensure the availability and security of your main servers, even during large-scale DDoS attacks.

## Configuration

The server is highly configurable through the `config.json` file. Here are the available configuration options:

- `ddosProtectionSystem` (string): The DDoS protection system to use. Supported values are `rateLimit`, `ipBlacklist`, and `cloudFlare`.
- `ddosProtectionServerPort` (integer): The port number on which the DDoS protection server should listen.
- `ddosProtectionServerIp` (string): The IP address on which the DDoS protection server should listen.
- `requestRateLimit` (integer): The maximum number of requests allowed within the specified rate period (in milliseconds).
- `requestRatePeriodMs` (integer): The time period (in milliseconds) for the request rate limit.
- `maxAvailablePorts` (integer): The maximum number of available ports for the main servers to connect to.
- `initialAvailablePorts` (array of integers): The list of initial available ports for the main servers to connect to.
- `discordWebhook` (string): The Discord webhook URL for logging DDoS attempts and events.
- `whitelistedIps` (object): A map of whitelisted IP addresses that should bypass DDoS protection checks. The keys are IP addresses, and the values are `true`.
- `blacklistThreshold` (integer): The threshold for the number of DDoS attempts after which an IP address should be blacklisted.
- `blacklistDurationMs` (integer): The duration (in milliseconds) for which an IP address should be blacklisted.
- `captchaEnabled` (boolean): A flag to enable or disable the captcha challenge mechanism.
- `captchaDifficulty` (string): The difficulty level for the captcha challenge (e.g., `easy`, `medium`, `hard`).
- `headersToAnalyze` (array of strings): A list of HTTP headers to analyze for potential DDoS attacks.
- `logFilePath` (string): The file path for the server log file.
- `logLevel` (string): The log level for the server logs (e.g., `INFO`, `WARNING`, `SEVERE`).
- `maxConcurrentConnections` (integer): The maximum number of concurrent connections the server should handle.
- `requestQueueSize` (integer): The size of the request queue for the server.
- `cloudFlareApiKey` (string): The API key for integrating with CloudFlare's DDoS protection service.
- `cloudFlareEmail` (string): The email associated with the CloudFlare account.

Refer to the `config.json` file in the repository for an example configuration.

## Getting Started

1. Clone the repository:
`git clone https://github.com/your-username/ddos-protection-server.git`

2. Build the project using your preferred Java build tool (e.g., Maven, Gradle).

3. Create the `config` and `logs` directories in the project root.

4. Configure the `config.json` file according to your requirements.

5. Run the `DDoSProtectionServer` class to start the server.

6. Use the provided API endpoints to manage connections, configure settings, and monitor the server's status.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License]



