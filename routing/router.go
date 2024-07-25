package routing 

import ( 
	"fmt" 
	"net" 
	"sync" 
	"time"
)

type BackendServer struct {
	IP   string `json:"ip"`
	Port int    `json:"port"` 
}
type Route struct {
	ID             int      `json:"id"`             
	FrontendIP     string   `json:"frontend_ip"`
	FrontendPort int      `json:"frontend_port"`
	BackendIP     string   `json:"backend_ip"`
	BackendPort int      `json:"backend_port"`
	ProtectionMode string   `json:"protection_mode"` 
	Blacklist       []string `json:"blacklist"`       

type RouteStats struct {
    TotalRequests int `json:"totalRequests"` 
    DataTransferred int64 `json:"dataTransferred"`
} 
  
type GlobalStats struct {
    TotalRequests int `json:"totalRequests"`
} 

var ( 
	routes      []*Route
	routingTable = make(map[string]*BackendServer) 
	currentID  = 1                                
	mutex        sync.RWMutex   
	globalStats GlobalStats        
)

func InitializeRouter(backendServers []BackendServer) error {
	mutex.Lock()
	defer mutex.Unlock()

	for _, server := range backendServers {
		if net.ParseIP(server.IP) == nil {
			return fmt.Errorf("invalid backend server IP address: %s", server.IP)
		}
		key := fmt.Sprintf("%s:%d", server.IP, server.Port)
		routingTable[key] = &server 
	}

	defaultRoute := &Route{
		ID:             currentID,
		FrontendIP:     "0.0.0.0",
		FrontendPort: 0, 
		BackendIP:     "192.168.1.10",
		BackendPort: 8000,
		ProtectionMode: "",        
		Blacklist:       []string{}, 
		Stats:           RouteStats{}, 
	}

	currentID++         
	routes = append(routes, defaultRoute)
	return nil
}

func AddRoute(frontendIP string, frontendPort int, backendIP string, backendPort int, cfg *Config) error {
	mutex.Lock() 
	defer mutex.Unlock()
	if frontendIP == "" || frontendPort <= 0 || backendIP == "" || backendPort <= 0 {
		return fmt.Errorf("invalid route parameters - IPs/Ports cannot be blank/zero")
	}
	newRoute := &Route{
		ID:             currentID,
		FrontendIP:     frontendIP,
		FrontendPort: frontendPort,
		BackendIP:     backendIP,
		BackendPort: backendPort,
		ProtectionMode: "",
		Blacklist:       []string{}, 
		Stats:           RouteStats{},
	}
	cfg.Routing = append(cfg.Routing, *newRoute)
	currentID++ 
	return nil
}

func RemoveRoute(frontendIP string, frontendPort int, cfg *Config) error {
	mutex.Lock()
	defer mutex.Unlock()

	indexToRemove := -1 
	for i, route := range cfg.Routing {
		if route.FrontendIP == frontendIP && route.FrontendPort == frontendPort {
			indexToRemove = i
			break 
		}
	}
	if indexToRemove != -1 {
		cfg.Routing = append(cfg.Routing[:indexToRemove], cfg.Routing[indexToRemove+1:]...)
		return nil
	}
	return fmt.Errorf("no matching route found with Frontend IP: %s and Port: %d", frontendIP, frontendPort)
}

func GetRouteByHostAndPort(host string, port int) (*Route, bool) {
	for _, route := range routes { 
		if route.FrontendPort == port && (route.FrontendIP == "0.0.0.0" || route.FrontendIP == host) {
			return route, true
		}
	}

	return nil, false
}

func ListRoutes(cfg *Config