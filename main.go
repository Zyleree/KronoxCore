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
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fortify/challenge"
	"fortify/ddos"
	"fortify/logging"
	"fortify/routing"

	"golang.org/x/time/rate"
)

type Config struct {
	ServerPort        int                    `json:"serverPort"`
	LogFile            string                 `json:"logFile"`
	ChallengePagePath string                 `json:"challengePagePath"`
	RateLimit        ddos.RateLimitConfig   `json:"rateLimit"`
	ProtectionMode   string                 `json:"protectionMode"` 
	GlobalBlacklist  []string               `json:"globalBlacklist"`
	Routing           []routing.Route        `json:"routing"`
	BackendServers    []routing.BackendServer `json:"backendServers"`
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

func saveConfig(filePath string, config *Config) error {
	data, err := json.MarshalIndent(config, "", "    ") 
	if err != nil {
		return fmt.Errorf("error marshalling config: %w", err)
	}
	return ioutil.WriteFile(filePath, data, 0644)
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
	logging.LogEvent("INFO", nil, "Fortify starting...")

	if err := routing.InitializeRouter(config.BackendServers); err != nil {
		logging.LogEvent("FATAL", nil, fmt.Sprintf("Error initializing router: %v", err))
		os.Exit(1)
	}

	ddosProtection, err := ddos.NewDDOSProtection(config.RateLimit)
	if err != nil {
		logging.LogEvent("FATAL", nil, fmt.Sprintf("Error initializing DDOS protection: %v", err))
		os.Exit(1)
	}

	challengeSystem := challenge.NewChallengeSystem(config.ChallengePagePath)

	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("> ")
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			processCommand(input, &config)
		}
	}()

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.ServerPort),
		Handler:      http.HandlerFunc(handleRequest(ddosProtection, challengeSystem, config)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		logging.LogEvent("INFO", nil, fmt.Sprintf("Fortify listening on port %d...", config.ServerPort))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.LogEvent("ERROR", nil, fmt.Sprintf("Server error: %v", err))
		}
	}()

	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)
	<-shutdownSignal
	logging.LogEvent("INFO", nil, "Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logging.LogEvent("ERROR", nil, fmt.Sprintf("Server shutdown error: %v", err))
	}

	logging.LogEvent("INFO", nil, "Server gracefully stopped")
}

func handleRequest(ddosProtection *ddos.DDOSProtection, challengeSystem *challenge.ChallengeSystem, cfg *Config) http.HandlerFunc {
	limiter := rate.NewLimiter(rate.Every(time.Second/10), 20)
	return func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.UserAgent()
		requestLog := logging.LogEntry{
			Level:     "INFO",
			Message:   "Incoming Request",
			Request: &logging.HTTPRequest{
				Method: r.Method,
				Host:   r.Host,
				URL:    r.URL.String(),
				From:   r.RemoteAddr,
				Agent:  userAgent,
			},
		}
		logging.LogEventCustom(requestLog)
		protectionMode := cfg.ProtectionMode

		route, routeExists := routing.GetRouteByHostAndPort(r.Host, r.Port)
		if routeExists {
			if route.ProtectionMode != "" {
				protectionMode = route.ProtectionMode 
			}

			if isBlacklisted(r.RemoteAddr, route.Blacklist) {
				logging.LogEvent("WARNING", r, fmt.Sprintf("Blocked blacklisted IP for route: %s", r.RemoteAddr))
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		if isBlacklisted(r.RemoteAddr, cfg.GlobalBlacklist) {
			logging.LogEvent("WARNING", r, fmt.Sprintf("Blocked globally blacklisted IP: %s", r.RemoteAddr))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if protectionMode == "web" {
			if ddosProtection.IsSuspicious(r) {
				logging.LogEvent("WARNING", r, fmt.Sprintf("Suspicious request detected from: %s", r.RemoteAddr))
				if !challengeSystem.IsAllowed(w, r) {
					logging.LogEvent("INFO", r, fmt.Sprintf("Challenge presented to: %s", r.RemoteAddr))
					return
				}
				logging.LogEvent("INFO", r, fmt.Sprintf("Challenge passed from: %s", r.RemoteAddr))
			}
		} else if protectionMode == "none" {
			if !limiter.Allow() { 
				logging.LogEvent("WARNING", r, fmt.Sprintf("Rate limit exceeded from: %s", r.RemoteAddr))
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		if routeExists {
			backend := &routing.BackendServer{
				IP:   route.BackendIP,
				Port: route.BackendPort,
			}
			forwardRequest(backend, w, r)
		} else {
			logging.LogEvent("ERROR", r, fmt.Sprintf("No matching route found for %s", r.Host))
			http.Error(w, "Bad Gateway - No route found.", http.StatusBadGateway)
		}

	}
}

func forwardRequest(backend *routing.BackendServer, w http.ResponseWriter, r *http.Request) {
	backendURL := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", backend.IP, backend.Port),
	}
	logging.LogEvent("INFO", r, fmt.Sprintf("Forwarding request to backend: %s", backendURL))

	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	proxy.ErrorLog = log.New(logging.GetLogFile(), "[Reverse Proxy Error] ", log.LstdFlags)
	proxy.ServeHTTP(w, r)
}

func isBlacklisted(ip string, blacklist []string) bool {
	for _, blacklistedIP := range blacklist {
		if ip == blacklistedIP {
			return true
		}
	}
	return false
}
func processCommand(command string, config *Config) {
	parts := strings.Fields(command) 
	if len(parts) == 0 {
		return 
	}

	switch strings.ToLower(parts[0]) {
	case "help":
		fmt.Println("------------------------- Fortify Help ------------------------")
		fmt.Println("Available Commands: ")
		fmt.Println("    help                        : Displays this help message")
		fmt.Println("    addroute  <frontendIP> <frontendPort> <backendIP> <backendPort>        : Adds/updates a routing rule.")
		fmt.Println("    removeroute  <frontendIP> <frontendPort>         : Removes a routing rule.")
		fmt.Println("    listroutes                   :  Lists all configured routes.")
		fmt.Println("    setprotection <mode> [<routeID>]   : Set Protection mode (web/none/off), use route ID to set route specific mode")
		fmt.Println("    addblacklist  <ipAddress> [<routeID>]  : Add IP to blacklist (route specific with ID, otherwise global)")
		fmt.Println("    removeblacklist <ipAddress> [<routeID> : Remove from blacklist.")
		fmt.Println("--------------------------------------------------------------")

	case "addroute":
		if len(parts) != 5 {
			fmt.Println("Invalid usage. Syntax: addroute <frontend_ip> <frontend_port> <backend_ip> <backend_port>")
			return
		}
		frontendIP := parts[1]
		frontendPort, err := strconv.Atoi(parts[2])
		backendIP := parts[3]
		backendPort, err := strconv.Atoi(parts[4])

		if err != nil {
			fmt.Println("Invalid port number(s). Please use integers.")
			return
		}
		if err := routing.AddRoute(frontendIP, frontendPort, backendIP, backendPort, config); err != nil {
			fmt.Println("Error adding route:", err)
		} else {
			fmt.Println("Route added successfully!")
		}

	case "removeroute":
		if len(parts) != 3 {
			fmt.Println("Invalid usage. Syntax: removeroute <frontend_ip> <frontend_port>")
			return
		}
		frontendIP := parts[1]
		frontendPort, err := strconv.Atoi(parts[2])
		if err != nil {
			fmt.Println("Invalid port number. Please use an integer.")
			return
		}
		if err := routing.RemoveRoute(frontendIP, frontendPort, config); err != nil {
			fmt.Println("Error removing route:", err)
		} else {
			fmt.Println("Route removed successfully!")
		}

	case "listroutes":
		routing.ListRoutes(config)

	case "setprotection":
		if len(parts) < 2 || len(parts) > 3 {
			fmt.Println("Invalid usage: setprotection <mode> [<route_id>]")
			return
		}

		mode := strings.ToLower(parts[1])
		if mode != "web" && mode != "none" && mode != "off" {
			fmt.Println("Invalid protection mode. Choose from: 'web', 'none', or 'off'.")
			return
		}

		if len(parts) == 3 {
			routeIDStr := parts[2]
			routeID, err := strconv.Atoi(routeIDStr)
			if err != nil {
				fmt.Println("Invalid route ID. Please provide a number.")
				return
			}

			found := false
			for i := range config.Routing {
				if config.Routing[i].ID == routeID {
					config.Routing[i].ProtectionMode = mode
					found = true
					fmt.Printf("Protection mode for route ID %d set to '%s'\n", routeID, mode)
					break
				}
			}

			if !found {
				fmt.Printf("Route with ID %d not found.\n", routeID)
			}
		} else {
			config.ProtectionMode = mode
			fmt.Printf("Global protection mode set to '%s'\n", mode)
		}

		if err := saveConfig("config.json", config); err != nil {
			fmt.Println("Error saving config:", err) 
		}

	case "addblacklist":
		if len(parts) < 2 || len(parts) > 3 {
			fmt.Println("Invalid usage. Syntax: addblacklist <ip_address> [<route_id>]")
			return
		}

		ipAddress := parts[1]

		if len(parts) == 3 {
			routeIDStr := parts[2]
			routeID, err := strconv.Atoi(routeIDStr)
			if err != nil {
				fmt.Println("Invalid route ID. Please enter a valid number.")
				return
			}
			found := false
			for i, route := range config.Routing {
				if route.ID == routeID {
					config.Routing[i].Blacklist = append(config.Routing[i].Blacklist, ipAddress)
					fmt.Printf("IP address %s added to the blacklist for Route ID %d\n", ipAddress, routeID)
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("Route with ID %d not found.\n", routeID)
			}

		} else {
			config.GlobalBlacklist = append(config.GlobalBlacklist, ipAddress)
			fmt.Printf("IP address %s added to the GLOBAL blacklist\n", ipAddress)
		}
		if err := saveConfig("config.json", config); err != nil {
			fmt.Println("Error saving config:", err)
		}
	case "removeblacklist":
		if len(parts) < 2 || len(parts) > 3 {
			fmt.Println("Invalid usage: removeblacklist <ip_address> [<route_id>]")
			return
		}
		ipAddress := parts[1]
		if len(parts) == 3 {
			routeIDStr := parts[2]
			routeID, err := strconv.Atoi(routeIDStr)
			if err != nil {
				fmt.Println("Invalid route ID. Please provide a number.")
				return
			}

			found := false
			for i, route := range config.Routing {
				if route.ID == routeID {
					config.Routing[i].Blacklist = removeFromSlice(config.Routing[i].Blacklist, ipAddress)
					fmt.Printf("IP address %s removed from the blacklist for route ID %d\n", ipAddress, routeID)
					found = true
					break
				}
			}

			if !found {
				fmt.Printf("Route with ID %d not found.\n", routeID)
			}
		} else {
			config.GlobalBlacklist = removeFromSlice(config.GlobalBlacklist, ipAddress)
			fmt.Printf("IP Address %s removed from the GLOBAL blacklist\n", ipAddress)

		}
		if err := saveConfig("config.json", config); err != nil {
			fmt.Println("Error saving config:", err)
		}
	case "routestats":
		if len(parts) == 2 { 
			routeID, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Println("Invalid Route ID. Please enter a number.")
			}
			routeStats, err := routing.GetRouteStats(routeID, config)
			if err != nil {
				fmt.Println("Error: ", err) 
				return
			}
			fmt.Printf("------------ Route Stats for ID: %d ------------\n", routeID)
			fmt.Printf("Total Requests: %d\n", routeStats.TotalRequests)
		} else {
			globalStats := routing.GetGlobalStats(config)
			fmt.Println("------------ Global Stats ------------")
			fmt.Printf("Total Requests (Global): %d\n", globalStats.TotalRequests)
		}
	default:
		fmt.Println("Invalid command. Type 'help' for available commands.")
	}
}

func removeFromSlice(slice []string, item string) []string {
	for i, v := range slice {
		if v == item {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}