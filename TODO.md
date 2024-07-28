# TODOs - DDoS Protection Server

## High Priority

- **Implement Bot and DDoS Detection (Main.java):**
    - Replace placeholder comments in `isSuspiciousRequest()` with:
        - Enhanced Rate Limiting (consider sliding window, token bucket).
        - IP Reputation/Blacklist lookups. 
        - User-Agent analysis (detect bots).
        - Header Analysis (`Referer`, suspicious values).
        - Content Inspection (malicious payloads).
        - Behavioral Analysis (irregular patterns, timing).
        - Honeypots (attract and identify bots).
    - Research and add more robust DDoS detection methods. 

- **Verification Page Setup:**
    - Create your verification page (HTML, JavaScript, backend logic) to:
        - Present a CAPTCHA or challenge-response test.
        - Validate user responses.
        - Redirect valid users to the intended service.
    - Update `verificationPageURL` in `config.json`.

- **Error Handling:**
    - Add more comprehensive error handling (using try-catch blocks) in:
        - Request forwarding (`forwardRequest`, `forwardRequestToURL`).
        - Socket communication. 
    - Return appropriate HTTP status codes to clients on error (500, 502, etc.)

## Medium Priority

- **Implement ProtectSER logic (Main.java):**
    - In `handleProtectedRequest()`: 
        - Add request filtering, validation, and sanitization logic.
        - Consider API-specific protections:
            - Rate limiting per API key.
            - Payload validation against API schemas.

## Future Enhancements

- **API for Management:**
    - Develop a REST API for secure management: 
        - Add/delete connections.
        - View logs and metrics.
        - Configure the DDoS protection server.

- **Clustering/Scaling:**
    - If high availability and scalability are crucial, consider clustering multiple instances 
      of your DDoS protection server behind a load balancer.

- **Database/Caching:**
    - Explore persistent storage for:
        - Blacklists/whitelists for faster lookups.
        - Rate limiting data for accuracy across server restarts.
    - Use caching mechanisms (in-memory or distributed) to improve performance for 
      frequently accessed data (like configuration). 