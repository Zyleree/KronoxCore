# Fortify - Custom Go DDoS Protection Server 

## Introduction
This project is a basic but functional DDoS protection and traffic routing server implemented in Go.  
It uses a combination of rate limiting and a JavaScript-based challenge system to mitigate some basic DDoS attacks. 

## Features
- Basic Rate Limiting (Configurable per second). 
- IP Address-based Routing.
- JavaScript challenge to filter out bots. 
- Logging to file (fortify.log). 
- Console-based control for routing. 

## How to Use:

1. **Prerequisites:** Make sure you have Go installed on your system:  [https://go.dev/doc/install](https://go.dev/doc/install).

2. **Installation:**
   - Download or clone the Fortify source code repository to your machine. 

3. **Configuration:** 
   - Open the `config.json` file:
      ```json 
      {
        "serverPort": 8080,       // Port for Fortify to listen on
        "logFile": "logs/fortify.log", // Path to log file
        "challengePagePath": "challenge/challenge.html",  // Location of challenge HTML
        "rateLimit": {             
          "requestsPerSecond": 5   // Allowed requests per second per IP
        } 
      }
      ```
      - **Important:**  Customize the values in the `config.json` to match your network environment and desired settings: 
          - **`serverPort`:** The port on which Fortify will listen for incoming requests (e.g., 8080, 443).  
          - **`logFile`:** The path and filename for the log file.  A  `logs` folder will be created if it doesn't exist.
          - **`rateLimit.requestsPerSecond`:** Set this to your desired rate limit.
          - **Note:** More advanced DDoS mitigation configuration (like blacklisting) can be added in the future.

4.  **Running the Server:** 
     - **Terminal 1 (Run Fortify):**
        - Open your terminal and navigate to the root directory of the project.
        - Run Fortify: 
             ```bash 
             go run .
             ```
     -  **Terminal 2 (Manage Routes):**  
         -  **In a *second* terminal window**, (also in the Fortify project directory) you'll manage your backend server routes while Fortify runs:
            ```bash
            > addroute <frontend_ip> <frontend_port> <backend_ip> <backend_port>  
            ```
            -  For example:  This will redirect traffic from `127.0.0.1:12345` to a backend server listening on  `192.168.1.10:8000`:
               ```bash  
               > addroute 127.0.0.1 12345 192.168.1.10 8000  
               ```  

5. **Routing and Protection:**  
    - When traffic hits the `frontend_ip:frontend_port`, it will go through Fortify's checks and then, if safe, be routed to your  `backend_ip:backend_port`.
    - Fortify logs events to `fortify.log`, helping you monitor activity and attacks.   

## Contributing

This project is open to contributions for further development! If you'd like to add features (more sophisticated DDoS mitigation, web-based UI, etc.), feel free to fork the repository, make your changes, and submit a pull request.