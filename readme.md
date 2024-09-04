# KronoxCore

KronoxCore is a customizable Java-based proxy server designed for flexibility, security, and performance. It features different proxying modes, robust DDoS protection, CORS support, and the ability to create a server fleet using MariaDB for shared configuration and potential load balancing (future implementation).

## Key Features:

**1. Proxying Modes:**

-   **`forward`:** Directly forwards requests to the target server without any additional processing.
-   **`ddosprot`:**  Implements basic DDoS protection with rate limiting and temporary IP banning.
-   **`filterddosprot`:**  Adds advanced security by filtering (removing/sanitizing headers and cookies), encrypting the request, and then forwarding it to the target. Responses are decrypted before being sent back to the client.

**2. DDoS Protection:**

-   **Rate Limiting:** Limits the number of requests from a single IP within a defined time window.
-   **Path-Based Rate Limiting:** Allows for setting different rate limits per unique URL path.
-   **Temporary IP Banning:** Automatically bans IPs exceeding the rate limits for a configurable duration.

**3. Filtering and Sanitization:**

-   **Malicious Header Removal:**  Removes known dangerous headers from incoming requests (e.g., `Referer`, `X-Forwarded-For`).
-   **Cookie Sanitization:**  Filters cookies to remove potentially malicious characters and adds `HttpOnly` and `Secure` flags as configured.

**4. Encryption:**

-   **AES Encryption (CBC mode, PKCS5Padding):**  Used in  `filterddosprot`  mode for encrypting the entire request payload. 
-   **Secure Key Management:**  The encryption key is stored in  `config.properties`  and generated automatically if not present.

**5. Content Filtering:**

-   **`blocked_content.json`:** A list of URLs, keywords, or patterns that will trigger request blocking. 

**6. CORS Support:**

-   **Configurable `corsAllowedOrigins`:** Defines allowed origins for cross-origin requests, including the wildcard (%) to allow all origins.

**7. Fleet Mode and MariaDB Integration**

-   **Fleet Management:** KronoxCore servers can be grouped into a fleet, managed by a central MariaDB database.
    -   **Instance Registration:** Each server registers itself in the database with a unique ID, API key, and IP address/port. 
    -   **Network Information:** The `networkinfo` command displays reachable instances in the fleet.
-   **Shared Blocked Content (Future Implementation):** The `blocked_content` table in MariaDB (to be implemented) will be used to manage a common set of blocked content for the entire fleet. 

**8. Configuration Management**

-   **`config.properties`:**  Central configuration file for settings like:
    -   `availablePorts`: A comma-separated list of available ports for proxying.
    -   `ddosProtectionEnabled`: Boolean to enable/disable DDoS protection.
    -   `ddosTimeoutMinutes`: Duration for temporary IP bans.
    -   `corsAllowedOrigins`: Comma-separated list of allowed CORS origins.
    -   `encryptionKey`: The encryption key used for `filterddosprot` mode.
    -   `httpOnly`: Boolean to enable/disable the  `HttpOnly`  flag for cookies.
    -   `secureCookie`: Boolean to enable/disable the  `Secure`  flag for cookies.
    -   `defaultCsrfProtection`:  Boolean to enable/disable CSRF protection by default.
    -   `kronoxPort`: The port used for server-to-server communication (fleet mode).
    -   `mariaDbUrl`: Connection URL for the MariaDB database.
    -   `mariaDbUser`: Username for the MariaDB database.
    -   `mariaDbPassword`: Password for the MariaDB database.
    -   `fleetMode`:  Boolean to enable/disable fleet mode.
    -   `instanceName`:  Name of the current server instance.
    -   `instanceId`: Unique ID generated for each instance. 
    -   `apiKey`: API key generated for secure communication (fleet mode).
-   **Dynamic Reloading (`refreshconfig` Command):**  The configuration can be reloaded on-the-fly without restarting the server.

**9. Non-Blocking I/O and Thread Pooling:**

-   **NIO (Non-Blocking I/O):** Uses the `java.nio` package for handling multiple connections efficiently.
-   **Thread Pool (`ExecutorService`):**  Manages threads for handling client connections, ensuring better resource utilization.

**10. Detailed Access Logs:** 

-   Logs each request with timestamps, client IP, requested URL, target address, and other relevant data.

**Important Notes:**

-   KronoxCore assumes MariaDB is installed and accessible (local or remote). 
-   Secure your encryption key (`encryptionKey` in  `config.properties`) carefully. **Do not commit your key to version control!**
-   Make sure to create the `kronoxcore` database in MariaDB and configure the appropriate user credentials in `config.properties`.