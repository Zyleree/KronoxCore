# KronoxCore

KronoxCore is a customizable Java-based proxy server designed for flexibility, security, and performance. It features multiple proxying modes, robust DDoS protection, CORS support, in-memory caching, and the ability to create a server fleet using MariaDB for shared configuration and potential load balancing.

## Key Features:

**1. Proxying Modes:**

- **`forward`:** Directly forwards requests to the target server without additional processing.
- **`ddosprot`:** Implements basic DDoS protection with rate limiting and temporary IP banning.
- **`filterddosprot`:**  Adds advanced security: 
    - Filters (removes/sanitizes) headers and cookies.
    - Encrypts the request (AES encryption) before forwarding.
    - Decrypts responses before sending them to the client. 
- **`wafddosprot`:** Combines DDoS protection with a basic Web Application Firewall (WAF) for additional web-based security. 

**2. DDoS Protection:**

- **Rate Limiting:**  Limits requests from a single IP per time window.
- **Path-Based Rate Limiting:**  Allows different rate limits per URL path (future implementation).
- **Temporary IP Banning:** Automatically bans IPs that exceed the rate limits.

**3.  Web Application Firewall (WAF):**

- The `wafddosprot` mode provides basic protection against:
    - **SQL Injection (SQLi)**
    - **Cross-Site Scripting (XSS)**
    - **Command Injection** 
- You can easily add custom WAF rules using regular expressions.

**4. Filtering and Sanitization:**

- **Malicious Header Removal:**  Removes headers like `Referer`, `X-Forwarded-For`.
- **Cookie Sanitization:** Filters potentially malicious characters and adds `HttpOnly` and `Secure` flags.

**5.  Encryption:**

- **AES Encryption (CBC mode, PKCS5Padding):** Encrypts requests in `filterddosprot` mode. 
- **Secure Key Management:** The encryption key is stored in `config.properties` (and never committed to version control). It's auto-generated if not present.

**6. Caching (HTTP/1.1):**

- **In-Memory Cache:** Basic caching for faster responses to repeated requests.
- **Configurable Cache:** Cache size and expiration time can be configured in `config.properties`.

**7. Content Filtering:**

- **`blocked_content.json`:** A list of blocked URLs, keywords, or patterns.

**8. CORS Support:**

- **`corsAllowedOrigins`:**  Defines allowed origins for cross-origin requests (wildcard `%` allows all origins).

**9. Fleet Mode and MariaDB Integration:**

- **Centralized Management:** A MariaDB database is used to manage a fleet of KronoxCore instances.
    - **Instance Registration:** Each instance registers itself in the `cores` table with its ID, encryption key, IP address, and port.
    - **Link Management:**  Links are stored in the `links` table along with the `instanceId` of the server that created them. 
    - **Network Information:**  The `networkinfo` command displays reachable instances in the fleet.
- **Load Balancing (Future Implementation):** Planned support for load balancing across multiple KronoxCore instances. 

**10.  HTTP/1.1 and HTTP/2 Support:**

- **Configurable `httpVersion`:** Choose between HTTP/1.1 and HTTP/2 in `config.properties`. 
- **Jetty Integration:**  HTTP/2 is implemented using the Jetty library. You will need to provide an SSL keystore for HTTPS with HTTP/2.

**11.  Configuration Management:**

- **`config.properties`:**
    - `availablePorts`: Comma-separated list of ports for proxying.
    - `ddosProtectionEnabled`: Enables/disables DDoS protection.
    - `ddosTimeoutMinutes`:  Duration of temporary IP bans.
    - `corsAllowedOrigins`:  Allowed CORS origins.
    - `encryptionKey`: Encryption key (for `filterddosprot`).
    - `httpOnly` and `secureCookie`: Flags for cookies.
    - `defaultCsrfProtection`:  Enable/disable CSRF protection by default.
    - `kronoxPort`:  Port for server-to-server communication (fleet mode).
    - `mariaDbIp`:  MariaDB server IP address.
    - `mariaDbPort`: MariaDB server port. 
    - `mariaDbUser`:  MariaDB username.
    - `mariaDbPassword`: MariaDB password. 
    - `mariaDbDatabase`:  MariaDB database name.
    - `instanceName`: KronoxCore instance name. 
    - `instanceId`:  Unique instance ID (auto-generated).
    - `apiKey`: Instance API key (auto-generated).
    - `httpVersion`:  `HTTP/1.1` or `HTTP/2`.
    - `cacheSize`: Maximum entries in the cache. 
    - `cacheExpirationMinutes`: Cache entry expiration time. 
- **Dynamic Reloading (`refreshconfig`):** Reload configuration without restarting. 

**12. Non-Blocking I/O and Thread Pooling:**

- Uses NIO (`java.nio`) for efficiency.
- Manages threads with `ExecutorService` for better resource usage.

**13. Detailed Access Logs:**

- Logs request details (timestamp, client IP, URL, target address, etc.)

**Important Notes:**

- MariaDB needs to be installed and configured.
- Secure your encryption key (`encryptionKey`). **Do not commit it to version control!**

**Future Implementations:**

- Path-based rate limiting.
- Load balancing across KronoxCore instances.
- Shared `blocked_content` management across the fleet using MariaDB.