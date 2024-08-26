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
- **IP Reputation System (In Development):**  The server has an `IpReputation` class for future expansion of more advanced scoring, tracking, and response actions based on IP behavior. 

**Sanitization:**

- **Malicious Header Removal:** In `filterddosprot` mode, potentially dangerous headers are removed from client requests to reduce vulnerabilities. These headers can include:
    - `Cookie` (Handled separately)
    - `Referer`
    - `User-Agent` 
    - `X-Forwarded-For`
    - `X-Forwarded-Host`
- **Cookie Sanitization:**
    - The `filterddosprot` mode also sanitizes cookies, rejecting any cookie that contains characters outside of alphanumeric, hyphen, underscore, and period. 

**Encryption:**

- **`filterddosprot` Mode Encryption:**  This mode encrypts requests before sending them to the target server using AES encryption. It also decrypts the response before forwarding it back to the client.
- **Secure Key Management:** The encryption key (`ENCRYPTION_KEY`) is **generated randomly at server startup**.  **You MUST replace the placeholder in the `LinkManager` with a strong, secure key and manage it carefully**  for real-world usage. Ideally, store the key in an environment variable or a secure configuration file, **never in the source code directly.**

**CORS Support:**

- **`corsAllowedOrigins` Configuration:** You can configure a list of allowed origins for CORS in the `config.json` file. 
- **`%` Wildcard:** The `%` wildcard in `corsAllowedOrigins` allows all origins, which is useful for development or open APIs, but consider stricter restrictions for production environments.


## Getting Started:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Zyleree/KronoxCore
   ```

2. **Create directories:** 
   ```bash
   mkdir config
   mkdir logs
   ```

3. **Configure the server:**
   - Open `config/config.json` and adjust the settings:
     ```json
     {
       "availablePorts": [8000, 8001, 8002, 8003, 8004], 
       "ddosProtectionEnabled": true,           
       "ddosTimeoutMinutes": 30,                
       "corsAllowedOrigins": ["https://allowed-origin.com", "%"]
     }
     ```
    - **Important:** 
        - In the `LinkManager` class **REPLACE** the `ENCRYPTION_KEY` placeholder (`private static final String ENCRYPTION_KEY = generateRandomKey(256);`) with a strong, secure encryption key and **store it safely**. Do not commit the real key to version control.
        - Change  `https://allowed-origin.com`  in  `corsAllowedOrigins` with the origins you want to allow or use `%` for all origins (for development only).

4. **Compile and Run:** 
   - Navigate to your project directory in your terminal.
   - Compile the code:  `javac src/main/java/Main.java`
   - Run the server:  `java -cp src/main/java Main` 

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
- **`help`**: Shows the list of available commands.
- **`exit`**:  Shuts down the server. 


## Example:

1. **Add a secure link with filtering and encryption:**
   ```
   linkadd securelink https://api.example.com:443 filterddosprot
   ```

2. **Start the link:**
   ```
   linkstart securelink
   ```

Now, requests sent to  `localhost:8000`  (or whichever port is assigned) will be:

- Sanitized
- Encrypted
- Forwarded to  `https://api.example.com:443`

The response will be:

- Decrypted
- Forwarded back to the client

## Disclaimer:

While this proxy server incorporates basic security measures, you should adapt and extend the provided code to meet your specific requirements, especially regarding DDoS mitigation, encryption key management, and advanced request sanitization for production use. 

**This project is a foundation, not a finished solution.** Conduct thorough testing and consult security best practices for your environment before deploying this server in a production scenario! 
```
