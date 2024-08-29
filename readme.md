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
- **IP Reputation System (In Development):**  The server has an `IpReputation` class for future expansion of more advanced scoring, tracking, and response actions based on IP behavior. 

**Sanitization:**

- **Malicious Header Removal:** In `filterddosprot` mode, potentially dangerous headers are removed from client requests to reduce vulnerabilities. These headers can include:
    - `Cookie` (Handled separately)
    - `Referer`
    - `User-Agent` 
    - `X-Forwarded-For`
    - `X-Forwarded-Host`
- **Cookie Sanitization:**
    - The `filterddosprot` mode also sanitizes cookies, rejecting any cookie that contains characters outside of alphanumeric, hyphen, underscore, period, "=", "%", ".", ";", and " " (space).

**Encryption:**

- **`filterddosprot` Mode Encryption:**  This mode encrypts requests before sending them to the target server using AES encryption. It also decrypts the response before forwarding it back to the client.
- **Secure Key Management:**  The encryption key is **now managed in `config/config.json`**. If no key is present in the file, the server will generate a random key at startup and store it. 
    - **Important:** Never hardcode encryption keys directly into your source code, especially when committing to version control!

**Content Filtering:**

- **`blocked_content.json`:** This file in the `config` directory allows you to list content (URLs, keywords, etc.) to be blocked. The server will reject requests that contain this content.

**CORS Support:**

- **`corsAllowedOrigins` Configuration:** You can configure a list of allowed origins for CORS in the `config/config.json` file. 
- **`%` Wildcard:** The `%` wildcard in `corsAllowedOrigins` allows all origins, which is useful for development or open APIs, but consider stricter restrictions for production environments.

## Getting Started:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Zyleree/KronoxCore
   ```

2. **Compile and Run:** 
   - Navigate to your project directory in your terminal.
   - Compile the code:  `javac src/main/java/Main.java`
   - Run the server:  `java -cp src/main/java Main` 

    The `config` and `logs` directory will be created automatically in your project root if it does not already exist

3. **Configure the server:**
   - Open `config/config.json` and adjust the settings:
     ```json
     {
       "availablePorts": [8000, 8001, 8002, 8003, 8004],
       "ddosProtectionEnabled": true,          
       "ddosTimeoutMinutes": 30,               
       "corsAllowedOrigins": ["https://allowed-origin.com", "%"],
       "encryptionKey": "YOUR_ENCRYPTION_KEY_HERE" 
     }
     ```
    - **Important:** 
        - **Replace `YOUR_ENCRYPTION_KEY_HERE` with a strong, randomly generated encryption key. Do not use this placeholder key in a real environment!**
        - Change  `https://allowed-origin.com`  in  `corsAllowedOrigins` with the origins you want to allow, or use `%` for all origins (for development only).
    -  Add content you want to block in `config/blocked_content.json`, one entry per line. 

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

Now, requests sent to  `localhost:8000` (or whichever port is assigned) will be:

- Sanitized
- Encrypted
- Forwarded to  `https://api.example.com:443`

The response will be:

- Decrypted
- Forwarded back to the client

## Disclaimer:

While this proxy server incorporates basic security measures, you should adapt and extend the provided code to meet your specific requirements, especially regarding DDoS mitigation, encryption key management, and advanced request sanitization for production use. 

**This project is a foundation, not a finished solution.** Conduct thorough testing and consult security best practices for your environment before deploying this server in a production scenario! 