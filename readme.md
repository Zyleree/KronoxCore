# KronoxCore

This is a customizable Java proxy server that features:

- **Simple Forwarding (`forward` mode)**
- **Basic and Enhanced DDoS Protection:** (`ddosprot` and `filterddosprot` modes)
- **CORS Support:** Allows cross-origin requests based on configurable allowed origins.

## Features:

**Proxying Modes:**

- **`forward`:** Forwards requests directly to the target server without DDoS protection.
- **`ddosprot`:** Provides basic DDoS protection using rate limiting and temporary IP banning.
- **`filterddosprot`:** Adds an extra layer of security by sanitizing and encrypting requests before forwarding them.

**DDoS Protection:**

- **Rate Limiting:** The server limits the number of requests a client can make within a one-second window to prevent potential attacks. If exceeded, the IP is temporarily banned. 
- **Temporary IP Banning:**  IPs identified as exceeding the request rate limit are automatically banned for a short duration to mitigate DDoS attempts.
- **Path-Based Rate Limiting:**  The `ddosprot` mode now supports separate rate limits for each unique URL path, allowing for more granular control over allowed requests.

**Sanitization:**

- **Malicious Header Removal:** In `filterddosprot` mode, potentially dangerous headers are removed from client requests to reduce vulnerabilities. These headers can include:
    - `Cookie` (Handled separately)
    - `Referer`
    - `User-Agent` 
    - `X-Forwarded-For`
    - `X-Forwarded-Host`
- **Cookie Sanitization:**
    - The `filterddosprot` mode also sanitizes cookies, rejecting any cookie that contains characters outside of alphanumeric, hyphen, underscore, period, "=", "%", ".", ";", and " " (space).
    - **HTTPOnly and Secure Flags:** You can now configure `HttpOnly` and `Secure` flags for cookies in the `config.properties` file to enhance cookie security. 

**Encryption:**

- **`filterddosprot` Mode Encryption:**  This mode encrypts requests before sending them to the target server using AES encryption. It also decrypts the response before forwarding it back to the client.
- **Secure Key Management:**  The encryption key is now managed in `config/config.properties`. If no key is present in the file, the server will generate a random key at startup and store it. 
    - **Important:** Never hardcode encryption keys directly into your source code, especially when committing to version control!

**Content Filtering:**

- **`blocked_content.json`:** This file in the `config` directory allows you to list content (URLs, keywords, etc.) to be blocked. The server will reject requests that contain this content.

**CORS Support:**

- **`corsAllowedOrigins` Configuration:** You can configure a list of allowed origins for CORS in the `config/config.properties` file. 
- **`%` Wildcard:** The `%` wildcard in `corsAllowedOrigins` allows all origins, which is useful for development or open APIs, but consider stricter restrictions for production environments.

**Other Improvements:**

- **Non-blocking I/O (NIO):** The proxy server now uses NIO for better performance and scalability.
- **Thread Pooling:**  A thread pool is used to handle client connections more efficiently.
- **Buffering:** Data is buffered for improved network I/O performance.
- **Detailed Logging:**  Detailed access logs are generated, including timestamps, client IP addresses, request methods, URLs, target addresses, and response codes.
- **Dynamic Configuration Reloading:** You can reload the `config.properties` file using the `refreshconfig` command without restarting the server.

## Getting Started:

1. **Compile and Run:** 
   - Navigate to your project directory in your terminal.
   - Compile the code:  `javac src/main/java/Main.java`
   - Run the server:  `java -cp src/main/java Main` 

    The `config` and `logs` directory will be created automatically in your project root if it does not already exist

2. **Configure the server:**
   - Open `config/config.properties` and adjust the settings. A default config file will be generated with these default settings: 
     ```properties
     availablePorts=8000,8001,8002,8003,8004
     ddosProtectionEnabled=false
     ddosTimeoutMinutes=30
     corsAllowedOrigins=%
     encryptionKey=
     httpOnly=false
     secureCookie=false
     defaultCsrfProtection=false
     ```
    - **Important:** 
        - **Replace the empty `encryptionKey` value with a strong, randomly generated encryption key. Do not use this placeholder key in a real environment!**
        - Change the `corsAllowedOrigins` value to the origins you want to allow, or use `%` for all origins (for development only).
    -  Add content you want to block in `config/blocked_content.json`, one entry per line. 

3. **Configure Links:**
    - You can define links in `config/links.properties` using this format:
        ```properties
        link.<linkName>=<targetAddress>,<assignedPort>,<mode>,<active>,<csrfProtection>,<csrfToken>
        ```
        - For example:
        ```properties
        link.myapi=api.example.com:443,8000,filterddosprot,true,true,your-csrf-token
        ```

## Usage - Server Commands:

The server uses interactive commands:

- **`linkadd <name> <targetAddress:port> <mode>`**:
    - Adds a new proxy link. 
    - `<name>`: Unique name for the link.
    - `<targetAddress:port>`: Address and port of the target server (e.g., `example.com:80`).
    - `<mode>`:  `forward`, `ddosprot`, or `filterddosprot`.
- **`linkremove <name>`**: Removes a proxy link.
- **`linkstart <name>`**:  Starts a proxy link. The proxy starts listening on the assigned port.
- **`linkstop <name>`**:  Stops a proxy link.
- **`blockcontent <content>`**: Adds content to be blocked by the proxy. 
- **`refreshconfig`**: Reloads the `config.properties` file. 
- **`help`**: Shows the list of available commands.
- **`exit`**:  Shuts down the server. 

## Example:

1.  **Add a secure link with filtering and encryption:**
    ```bash
    linkadd myapi api.example.com:443 filterddosprot
    ```

2.  **Start the link:**
    ```bash
    linkstart myapi
    ```

Now, requests sent to `localhost:8000` (or whichever port is assigned) will be:

- Sanitized
- Encrypted
- Forwarded to `https://api.example.com:443`

The response will be:

- Decrypted
- Forwarded back to the client

## Disclaimer:

While this proxy server incorporates basic security measures, you should adapt and extend the provided code to meet your specific requirements, especially regarding DDoS mitigation, encryption key management, and advanced request sanitization for production use. 

**This project is a foundation, not a finished solution.** Conduct thorough testing and consult security best practices for your environment before deploying this server in a production scenario! 