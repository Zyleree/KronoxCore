package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fortify/challenge"
	"fortify/ddos"
	"fortify/logging"
	"fortify/routing"
)

// Config ...
type Config struct {
	ServerPort        int               `json:"serverPort"`
	LogFile            string            `json:"logFile"`
	ChallengePagePath string            `json:"challengePagePath"`
	RateLimit        ddos.RateLimitConfig  `json:"rateLimit"`
}

func loadConfig(filePath string) (*Config, error) {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	err = json.Unmarshal(file, &config)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %w", err)
	}

	return &config, nil
}

func main() {
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	if err := logging.SetupLogger(config.LogFile); err != nil {
		log.Fatalf("Failed to set up logger: %v", err)
	}
	defer logging.CloseLogFile()

	logging.LogEvent("INFO", "Fortify starting...")

	ddosProtection, err := ddos.NewDDOSProtection(config.RateLimit)
	if err != nil {
		logging.LogEvent("FATAL", fmt.Sprintf("Error initializing DDoS protection: %v", err))
        os.Exit(1)
	}

	challengeSystem := challenge.NewChallengeSystem(config.ChallengePagePath)

	go func() {
		for {
			fmt.Print("> ")
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)

			parts := strings.Fields(input)
			if len(parts) == 0 {
				continue
			}

			command := strings.ToLower(parts[0])
			switch command {
			case "addroute":
				if len(parts) != 5 {
					fmt.Println("Usage: addroute <frontend_ip> <frontend_port> <backend_ip> <backend_port>")
					continue
				}
				frontendPort, err := strconv.Atoi(parts[2])
				if err != nil {
					fmt.Println("Invalid frontend port:", err)
					continue
				}
				backendPort, err := strconv.Atoi(parts[4])
				if err != nil {
					fmt.Println("Invalid backend port:", err)
					continue
				}
				err = routing.AddRoute(parts[1], frontendPort, parts[3], backendPort)
				if err != nil {
					fmt.Println("Error adding route:", err)
				}

			case "removeroute":
				if len(parts) != 3 {
					fmt.Println("Usage: removeroute <frontend_ip> <frontend_port>")
					continue
				}
				frontendPort, err := strconv.Atoi(parts[2])
				if err != nil {
					fmt.Println("Invalid frontend port:", err)
					continue
				}
				routing.RemoveRoute(parts[1], frontendPort)

			case "help":
				fmt.Println("Available commands: addroute, removeroute, help")

			default:
				fmt.Println("Invalid command. Type 'help' for a list of commands.")
			}
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logging.LogEvent("INFO", fmt.Sprintf("Request from %s to %s", r.RemoteAddr, r.URL))

		if ddosProtection.IsSuspicious(r) {
			logging.LogEvent("WARNING", fmt.Sprintf("Suspicious request detected from %s", r.RemoteAddr))
            if !challengeSystem.IsAllowed(w, r) {
                logging.LogEvent("INFO", fmt.Sprintf("Challenge presented to  %s", r.RemoteAddr))
				return 
			}
            logging.LogEvent("INFO", fmt.Sprintf("Challenge Passed from  %s", r.RemoteAddr))
		}

		host, portStr, _ := net.SplitHostPort(r.RemoteAddr)
		port, _ := strconv.Atoi(portStr)
		backend, err := routing.GetBackendServer(host, port)
		if err != nil {
			logging.LogEvent("ERROR", fmt.Sprintf("Routing error: %v", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

        forwardRequest(backend, w, r)
	})

	logging.LogEvent("INFO", fmt.Sprintf("Listening on port %d...", config.ServerPort))
	err = http.ListenAndServe(fmt.Sprintf(":%d", config.ServerPort), nil)
	if err != nil {
		logging.LogEvent("ERROR", fmt.Sprintf("Server error: %v", err))
	}
}

func forwardRequest(backend *routing.BackendServer, w http.ResponseWriter, r *http.Request) {
	backendURL := &url.URL{
		Scheme: "http", 
		Host:   fmt.Sprintf("%s:%d", backend.IP, backend.Port),
	}

	proxy := httputil.NewSingleHostReverseProxy(backendURL)
    proxy.ErrorLog = log.New(logFile, "[Reverse Proxy Error] ", log.LstdFlags)  // Log proxy errors to Fortify's log

    // Logging Successful Requests 
    logging.LogEvent("INFO", fmt.Sprintf("Forwarding request from %s to %s", r.RemoteAddr, backendURL)) 
	proxy.ServeHTTP(w, r) 
}